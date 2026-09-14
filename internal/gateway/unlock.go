package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Client unlocks (Slice 6): the model.ApprovalGate methods for unlocks, the
// reconcile loop that applies their deadlines, and what an unlock beginning or
// ending means for the access requests made under it. See
// docs/handoffs/2026-09-11-slice-6-contract.md, section B1.
//
// The gate methods run outside any MCP call, on behalf of the technician in
// the companion. Once a decision is durable its effects must follow even if
// the companion's request goes away, so they run detached from its
// cancellation; each endpoint call is still bounded by the RPC timeout. An
// audit entry that cannot be written is logged rather than returned: the
// decision is already durable, and the gateway withholds only content, of
// which a decision has none.

// errUnlocksOff answers a gate call on a gateway without technician approval.
var errUnlocksOff = fmt.Errorf("gateway: technician approval is off: %w", model.ErrInvalid)

// ApproveUnlock activates an unlock the technician approved in the companion
// and forwards every access request waiting for it. approval is what the
// companion built on the technician's sign-in; it must sign exactly what the
// row says now, name a live passkey of the row's technician, and arrive within
// CeremonyTimeout of the companion fixing the unlock's expiry. Activating it
// locks any other client the technician had unlocked, and ends that client's
// grants.
func (g *Gateway) ApproveUnlock(ctx context.Context, id string, approval proto.TechnicianApproval) (model.Unlock, error) {
	if !g.technicianApproval() {
		return model.Unlock{}, errUnlocksOff
	}
	row, err := g.ownUnlock(ctx, id, approval.Technician)
	if err != nil {
		return model.Unlock{}, err
	}
	now := g.now().UTC()
	switch {
	case row.State != model.UnlockAwaiting:
		return row, fmt.Errorf("gateway: unlock %s is %s, not awaiting approval: %w", id, row.State, model.ErrConflict)
	case row.ExpiresAt == nil:
		return row, fmt.Errorf("gateway: the companion has not fixed unlock %s's expiry: %w", id, model.ErrInvalid)
	}
	if state, _ := row.Due(now); state != "" {
		return row, fmt.Errorf("gateway: unlock %s passed its deadline unanswered: %w", id, model.ErrExpired)
	}
	if err := g.checkApproval(ctx, row.Technician, row.Approval(), approval); err != nil {
		return row, err
	}
	// The companion fixed ExpiresAt = approval + Duration, so it began
	// approving at ExpiresAt - Duration.
	if begun := row.ExpiresAt.Add(-row.Duration); now.Sub(begun) > model.CeremonyTimeout {
		return row, fmt.Errorf("gateway: unlock %s's expiry was fixed more than %s ago: %w", id, model.CeremonyTimeout, model.ErrExpired)
	}
	var assertion []byte
	if approval.Assertion != nil {
		if assertion, err = json.Marshal(approval.Assertion); err != nil {
			return row, fmt.Errorf("gateway: unlock %s: assertion: %w", id, err)
		}
	}
	active, locked, err := g.approvals.ActivateUnlockTx(ctx, id, func(u *model.Unlock) error {
		switch {
		case !model.UnlockAdvance(u.State, model.UnlockActive):
			return fmt.Errorf("gateway: unlock %s is %s: %w", u.ID, u.State, model.ErrConflict)
		case !u.Approval().SameSigned(approval):
			// Another approval after the checks above rotated the nonce or
			// the expiry: this approval signs what the row no longer says.
			return fmt.Errorf("gateway: unlock %s changed while it was being approved: %w", u.ID, model.ErrConflict)
		}
		decided := approval.ApprovedAt // exactly, so SignedApproval reproduces what was signed
		u.State, u.DecidedAt, u.Credential, u.Assertion = model.UnlockActive, &decided, approval.Credential, assertion
		return nil
	}, now)
	if err != nil {
		return active, err
	}
	ctx = context.WithoutCancel(ctx)
	_ = g.auditUnlock(ctx, active)
	for _, o := range locked {
		_ = g.auditUnlock(ctx, o)
		g.endUnlockAccess(ctx, o)
	}
	g.forwardUnlocked(ctx, active)
	return active, nil
}

// DenyUnlock refuses an unlock that is still awaiting approval, and every
// request waiting for it.
func (g *Gateway) DenyUnlock(ctx context.Context, id, technician, credential string) (model.Unlock, error) {
	if !g.technicianApproval() {
		return model.Unlock{}, errUnlocksOff
	}
	if _, err := g.ownUnlock(ctx, id, technician); err != nil {
		return model.Unlock{}, err
	}
	return g.endUnlock(ctx, id, func(model.Unlock) (string, string) { return model.UnlockDenied, model.ReasonDenied },
		func(u *model.Unlock, now time.Time) { u.Credential, u.DecidedAt = credential, &now })
}

// Lock ends an unlock early, awaiting or active: the requests waiting for it
// are denied and the grants made under it end, at the relay and at their
// endpoints. reason defaults to model.ReasonLocked.
func (g *Gateway) Lock(ctx context.Context, id, technician, reason string) (model.Unlock, error) {
	if !g.technicianApproval() {
		return model.Unlock{}, errUnlocksOff
	}
	if _, err := g.ownUnlock(ctx, id, technician); err != nil {
		return model.Unlock{}, err
	}
	reason = cmp.Or(strings.TrimSpace(reason), model.ReasonLocked)
	return g.endUnlock(ctx, id, func(model.Unlock) (string, string) { return model.UnlockLocked, reason }, nil)
}

// LockAll locks every open unlock of the technician: what signing out of the
// companion does. One that ends on its own meanwhile is not an error.
func (g *Gateway) LockAll(ctx context.Context, technician, reason string) error {
	if !g.technicianApproval() {
		return errUnlocksOff
	}
	open, err := g.approvals.Unlocks(ctx, technician, g.now())
	if err != nil {
		return fmt.Errorf("gateway: unlocks of %s: %w", technician, err)
	}
	var errs []error
	for _, u := range open {
		if model.UnlockTerminal(u.State) {
			continue
		}
		if _, err := g.Lock(ctx, u.ID, technician, reason); err != nil && !errors.Is(err, model.ErrConflict) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reconcileUnlocks expires unanswered and idle unlocks and those past their
// lifetime, and ends their grants. doOp already refuses a call under an
// unlock that is not live; this makes the end durable, revokes the grants at
// their endpoints and denies the requests left waiting.
func (g *Gateway) reconcileUnlocks(ctx context.Context) {
	if !g.technicianApproval() {
		return
	}
	open, err := g.approvals.UnlocksOpen(ctx)
	if err != nil {
		g.log.Error("gateway: could not list open unlocks", "err", err)
		return
	}
	now := g.now()
	for _, u := range open {
		if ctx.Err() != nil {
			return
		}
		if state, _ := u.Due(now); state != "" {
			g.expireUnlock(ctx, u.ID, now)
		}
	}
}

// expireUnlock ends an unlock its own deadlines have ended as of now.
func (g *Gateway) expireUnlock(ctx context.Context, id string, now time.Time) {
	_, err := g.endUnlock(ctx, id, func(u model.Unlock) (string, string) { return u.Due(now) }, nil)
	if err != nil && !errors.Is(err, model.ErrConflict) {
		g.log.Error("gateway: could not expire an unlock", "unlock", id, "err", err)
	}
}

// ownUnlock returns the unlock id when it belongs to technician. Another
// technician's unlock is indistinguishable from one that does not exist.
func (g *Gateway) ownUnlock(ctx context.Context, id, technician string) (model.Unlock, error) {
	u, err := g.approvals.Unlock(ctx, id)
	switch {
	case errors.Is(err, model.ErrNotFound) || (err == nil && (technician == "" || u.Technician != technician)):
		return model.Unlock{}, fmt.Errorf("gateway: unlock %s: %w", id, model.ErrNotFound)
	case err != nil:
		return model.Unlock{}, err
	}
	return u, nil
}

// endUnlock moves an unlock to the terminal state next picks from the row as
// stored, sets when and why it ended, applies update, and then ends what the
// unlock authorised: the requests waiting for it are denied and its grants
// terminated. next returns "" to leave the row alone, which is ErrConflict,
// as is a row that cannot make the move.
func (g *Gateway) endUnlock(ctx context.Context, id string, next func(model.Unlock) (state, reason string), update func(*model.Unlock, time.Time)) (model.Unlock, error) {
	ended := g.now().UTC()
	u, err := g.approvals.UpdateUnlockTx(ctx, id, func(u *model.Unlock) error {
		state, reason := next(*u)
		if state == "" || !model.UnlockAdvance(u.State, state) {
			return fmt.Errorf("gateway: unlock %s is %s: %w", u.ID, u.State, model.ErrConflict)
		}
		u.State, u.Reason, u.EndedAt = state, reason, &ended
		if update != nil {
			update(u, ended)
		}
		return nil
	})
	if err != nil {
		return u, err
	}
	ctx = context.WithoutCancel(ctx)
	_ = g.auditUnlock(ctx, u)
	g.endUnlockAccess(ctx, u)
	return u, nil
}

// endUnlockAccess ends everything an unlock that has ended authorised or was
// waiting to authorise, each with the unlock's reason: requests still waiting
// for it are denied, and the rest (pending at their endpoints or granted) are
// terminated through the end_access path, at the relay and then at the
// endpoint.
func (g *Gateway) endUnlockAccess(ctx context.Context, u model.Unlock) {
	rows, err := g.approvals.AccessForUnlock(ctx, u.ID)
	if err != nil {
		g.log.Error("gateway: could not list the requests of an ended unlock", "unlock", u.ID, "err", err)
		return
	}
	args := unlockArgs(u, true)
	for _, a := range rows {
		switch {
		case model.AccessTerminal(a.State):
		case a.State == model.AccessRequested || a.State == model.AccessAwaitingUnlock:
			g.endWaiting(ctx, rowCaller(a), a.ID, model.AccessDenied, u.Reason, args)
		default:
			g.endGrant(ctx, a, u.Reason, args)
		}
	}
}

// endGrant terminates one request made under an unlock that has ended, then
// revokes it at its endpoint, and audits it as end_access does.
func (g *Gateway) endGrant(ctx context.Context, a model.AccessRequest, reason string, args json.RawMessage) {
	stored, sent, err := g.terminate(ctx, a.ID, reason, g.now().UTC())
	switch {
	case errors.Is(err, model.ErrConflict):
		return // it ended on its own meanwhile
	case err != nil:
		// The unlock is no longer live, so doOp refuses every call under this
		// grant anyway; the endpoint keeps it until it expires.
		g.log.Error("gateway: could not terminate a grant of an ended unlock", "access", a.ID, "unlock", a.Unlock, "err", err)
		return
	}
	g.lapseChanges(ctx, stored, reason)
	result, why := audit.ResultDenied, reason
	if sent {
		if ce := g.revokeAtEndpoint(ctx, stored, proto.Caller{Tech: stored.Technician, Session: stored.Session}); ce != nil {
			result, why = audit.ResultError, reason+"; endpoint revocation failed: "+ce.msg
		}
	}
	if err := g.auditConsent(ctx, rowCaller(stored), stored, stored.State, args, result, why); err != nil {
		g.log.Error("gateway: could not audit a grant ended with its unlock", "access", a.ID, "err", err)
	}
}

// endWaiting ends a request that is still waiting (for an unlock, or for its
// endpoint's decision) in state, with reason, and audits it. A request that
// has moved on meanwhile is left alone.
func (g *Gateway) endWaiting(ctx context.Context, c caller, id, state, reason string, args json.RawMessage) {
	now := g.now().UTC()
	stored, err := g.access.UpdateAccessTx(ctx, id, func(a *model.AccessRequest) error {
		if (a.State != model.AccessRequested && a.State != model.AccessAwaitingUnlock && a.State != model.AccessAwaiting) ||
			!model.AccessAdvance(a.State, state) {
			return fmt.Errorf("access %s is %s: %w", a.ID, a.State, model.ErrConflict)
		}
		a.State, a.Reason = state, reason
		if state == model.AccessDenied {
			a.DecidedAt = &now
		}
		return nil
	})
	switch {
	case errors.Is(err, model.ErrConflict):
		return
	case err != nil:
		g.log.Error("gateway: could not end a waiting access request", "access", id, "state", state, "err", err)
		return
	}
	if err := g.auditConsent(ctx, c, stored, state, args, audit.ResultDenied, reason); err != nil {
		g.log.Error("gateway: could not audit a waiting access request that ended", "access", id, "err", err)
	}
}

// forwardUnlocked sends every request waiting for u, now active, on to its
// endpoint.
func (g *Gateway) forwardUnlocked(ctx context.Context, u model.Unlock) {
	signed, err := u.SignedApproval()
	if err != nil {
		g.log.Error("gateway: an approved unlock carries no approval", "unlock", u.ID, "err", err)
		return
	}
	rows, err := g.approvals.AccessForUnlock(ctx, u.ID)
	if err != nil {
		g.log.Error("gateway: could not list the requests waiting for an unlock", "unlock", u.ID, "err", err)
		return
	}
	for _, a := range rows {
		if a.State == model.AccessAwaitingUnlock {
			g.forwardWaiting(ctx, u, signed, a)
		}
	}
}

// forwardWaiting moves one request that waited for u, now active, on to its
// endpoint: its consent window and its lifetime start again from now, the
// lifetime capped at the unlock's, and its idle timeout shrinks to fit, since
// the endpoint refuses an idle timeout longer than the grant. A request that
// can no longer be granted is denied with why, or expired if the unlock has no
// time left to give it. It returns the request as it then stands.
func (g *Gateway) forwardWaiting(ctx context.Context, u model.Unlock, approval proto.TechnicianApproval, a model.AccessRequest) model.AccessRequest {
	c, args, now := rowCaller(a), unlockArgs(u, true), g.now().UTC()
	// Waiting for the technician used none of the request's lifetime.
	expires := now.Add(a.ExpiresAt.Sub(a.RequestedAt))
	if u.ExpiresAt != nil && u.ExpiresAt.Before(expires) {
		expires = *u.ExpiresAt
	}
	client, dev, why := g.forwardable(ctx, a, now)
	switch {
	case !now.Before(expires):
		g.endWaiting(ctx, c, a.ID, model.AccessExpired, proto.ReasonExpired, args)
		return g.reread(ctx, a)
	case why != "":
		g.endWaiting(ctx, c, a.ID, model.AccessDenied, why, args)
		return g.reread(ctx, a)
	}
	deadline := now.Add(proto.ConsentTimeout)
	stored, err := g.advance(ctx, a.ID, model.AccessAwaiting, func(s *model.AccessRequest) {
		s.ExpiresAt, s.ConsentDeadline, s.IdleTimeout = expires, &deadline, min(s.IdleTimeout, expires.Sub(now))
	})
	switch {
	case errors.Is(err, model.ErrConflict):
		return stored // forwarded or ended meanwhile
	case err != nil:
		g.log.Error("gateway: could not forward a request waiting for an unlock", "access", a.ID, "unlock", u.ID, "err", err)
		return a
	}
	if err := g.auditConsent(ctx, c, stored, model.AccessAwaiting, args, audit.ResultOK, ""); err != nil {
		g.log.Error("gateway: could not audit a forwarded access request", "access", a.ID, "err", err)
	}
	if ce := g.forwardAccess(ctx, c, client, dev, stored, approval, args); ce != nil {
		g.log.Info("gateway: endpoint did not take a forwarded access request", "access", a.ID, "code", ce.code, "reason", ce.msg)
		return g.reread(ctx, stored)
	}
	return stored
}

// forwardable checks that a request which waited for an unlock can still be
// granted now, and returns its client and device, or why it cannot: the
// client was switched off or its policy changed while the request waited, the
// technician lost the client, or the device is gone or offline.
func (g *Gateway) forwardable(ctx context.Context, a model.AccessRequest, now time.Time) (model.Client, model.Device, string) {
	client, err := g.dir.Client(ctx, a.Client)
	switch {
	case err != nil:
		g.log.Error("gateway: client lookup failed", "client", a.Client, "err", err)
		return client, model.Device{}, "the client could not be looked up"
	case client.Disabled:
		return client, model.Device{}, "the MSP has switched off AI access for this client"
	case client.Policy.Version != a.PolicyVersion:
		return client, model.Device{}, "the client's policy changed while the request waited; request access again"
	}
	// A legacy client-bound session is scoped by its session, not the ACL.
	if g.acl != nil && !strings.HasPrefix(a.Session, model.PrefixSession+"_") {
		if ok, err := g.acl.TechnicianCanAccess(ctx, a.Technician, a.Client); err != nil || !ok {
			return client, model.Device{}, "the technician is not authorized for this client"
		}
	}
	dev, ce := g.resolveDevice(ctx, a.Client, a.Device)
	switch {
	case ce != nil:
		return client, dev, ce.msg
	case dev.RevokedAt != nil || dev.Expired(now):
		return client, dev, deviceLabel(dev) + " is no longer enrolled"
	case !dev.Online(now):
		return client, dev, offlineMessage(dev)
	}
	return client, dev, ""
}

// forwardAccess sends a request that is awaiting_consent to its endpoint with
// the technician's signed unlock, and requires the endpoint's
// acknowledgement. A request the endpoint did not take is denied with why, so
// it never waits for a decision that cannot come.
func (g *Gateway) forwardAccess(ctx context.Context, c caller, client model.Client, dev model.Device, a model.AccessRequest, approval proto.TechnicianApproval, args json.RawMessage) *callError {
	now := g.now().UTC()
	cr := proto.ConsentRequest{AccessID: a.ID, Client: a.Client, Device: a.Device, Technician: a.Technician, Purpose: a.Purpose,
		Operations: a.RequestedOperations, Paths: a.RequestedScope, Duration: a.ExpiresAt.Sub(now), ExpiresAt: a.ExpiresAt,
		IdleTimeout: a.IdleTimeout, PolicyVersion: a.PolicyVersion, Approval: &approval, EndpointConsent: a.EndpointConsent}
	b, _ := json.Marshal(cr)
	req := proto.Request{V: proto.Version, ID: model.NewID(model.PrefixRequest), Op: proto.OpRequestAccess, Args: b,
		Policy: client.Policy.For(dev.OS), Caller: proto.Caller{Tech: a.Technician, Session: a.Session}, Deadline: time.Now().Add(g.timeout)}
	ce := func() *callError {
		resp, ce := g.rpc(ctx, client.Slug, dev.ID, req)
		switch {
		case ce != nil:
			return ce
		case !resp.OK:
			return agentError(resp.Error)
		}
		if ce := checkIntegrity(resp); ce != nil {
			return ce
		}
		// The endpoint only acknowledges here; its decision arrives on
		// proto.EvtConsent and the relay records it.
		var d proto.ConsentDecision
		if err := json.Unmarshal(resp.Result, &d); err != nil {
			return failed(proto.ErrInternal, "malformed consent decision")
		}
		if d.State != proto.ConsentAwaiting {
			return failed(proto.ErrInternal, "the endpoint did not accept the access request")
		}
		return nil
	}()
	if ce != nil {
		g.endWaiting(ctx, c, a.ID, model.AccessDenied, ce.msg, args)
	}
	return ce
}

// reread returns the request as it is stored now, or a if it cannot be read.
func (g *Gateway) reread(ctx context.Context, a model.AccessRequest) model.AccessRequest {
	if cur, err := g.access.Access(ctx, a.ID); err == nil {
		return cur
	}
	return a
}

// unlockLive refuses a call under a grant whose technician unlock is no
// longer live, before anything reaches the machine. The endpoint holds the
// grant until it is revoked or expires, so enforcing the unlock's end falls to
// the relay, here and in reconcileUnlocks.
func (g *Gateway) unlockLive(ctx context.Context, a model.AccessRequest, now time.Time) *callError {
	if g.approvals == nil {
		return denied(proto.ErrGrantInvalid, "this access grant came from a technician unlock, and technician approval is off; request access again")
	}
	u, err := g.approvals.Unlock(ctx, a.Unlock)
	switch {
	case errors.Is(err, model.ErrNotFound), err == nil && (u.Technician != a.Technician || u.Client != a.Client):
		return denied(proto.ErrGrantInvalid, "the technician's unlock behind this access grant does not exist; request access again")
	case err != nil:
		g.log.Error("gateway: unlock lookup failed", "unlock", a.Unlock, "err", err)
		return failed(proto.ErrInternal, "the technician's unlock could not be checked")
	}
	if err := u.Live(now); err != nil {
		_, why := u.Due(now)
		return denied(proto.ErrGrantInvalid, "the technician's unlock of this client has ended ("+cmp.Or(u.Reason, why, err.Error())+
			"); request access again, and the technician will be asked to unlock it")
	}
	return nil
}

// recordUnlockUse records a device call that ran under an unlock, with the
// endpoint's answer: the companion's activity list, and what keeps the unlock
// from going idle. A failure to record is logged, never returned, because the
// call itself has happened.
func (g *Gateway) recordUnlockUse(ctx context.Context, id string, req proto.Request, device string, resp *proto.Response) {
	var args struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(req.Args, &args)
	act := model.UnlockActivity{Unlock: id, Time: g.now().UTC(), Op: req.Op, Device: device, Path: args.Path,
		Result: audit.ResultOK, Bytes: resp.Meta.Bytes}
	if !resp.OK {
		ce := agentError(resp.Error)
		act.Result, act.ErrorCode, act.Bytes = ce.result, ce.code, 0
	} else if ce := checkIntegrity(resp); ce != nil {
		act.Result, act.ErrorCode, act.Bytes = ce.result, ce.code, 0
	}
	if err := g.approvals.RecordUnlockUse(context.WithoutCancel(ctx), id, act); err != nil {
		g.log.Error("gateway: could not record a call under an unlock", "unlock", id, "op", req.Op, "err", err)
	}
}

// unlockAuditArgs is the Args of the audit entry of every transition
// technician approval makes: an unlock's own, and, with Unlock set, those of
// the requests it decided.
type unlockAuditArgs struct {
	Source     string     `json:"source"`
	Unlock     string     `json:"unlock,omitempty"`
	Credential string     `json:"credential,omitempty"`
	Purpose    string     `json:"purpose,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

func unlockArgs(u model.Unlock, forAccess bool) json.RawMessage {
	a := unlockAuditArgs{Source: "technician", Credential: u.Credential, Purpose: u.Purpose, ExpiresAt: u.ExpiresAt, Reason: u.Reason}
	if forAccess {
		a.Unlock = u.ID
	}
	b, _ := json.Marshal(a)
	return b
}

// auditUnlock records an unlock's transition to its current state in its
// client's chain, as the technician and MCP session it belongs to.
func (g *Gateway) auditUnlock(ctx context.Context, u model.Unlock) error {
	result := audit.ResultOK
	if model.UnlockTerminal(u.State) {
		result = audit.ResultDenied
	}
	e := audit.Entry{Kind: audit.KindConsent, Client: u.Client, Tech: u.Technician, SessionID: u.Session, RequestID: u.ID,
		Tool: "unlock." + u.State, Args: unlockArgs(u, false), Result: result, ErrorMessage: u.Reason}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := g.audit.Append(actx, &e); err != nil {
		g.log.Error("gateway: could not audit an unlock transition", "unlock", u.ID, "state", u.State, "err", err)
		return fmt.Errorf("audit unlock: %w", err)
	}
	return nil
}

// touchUnlock counts a step of the change gate, a submit or an approval, as
// use of the unlock behind a grant. Such a step reaches no machine, so doOp
// never records it; without this an unlock could idle out under a change the
// technician was about to approve, and the release would be refused. An
// unlock that is no longer live is left as it is.
func (g *Gateway) touchUnlock(ctx context.Context, id string) {
	if id == "" || g.approvals == nil {
		return
	}
	now := g.now().UTC()
	_, err := g.approvals.UpdateUnlockTx(context.WithoutCancel(ctx), id, func(u *model.Unlock) error {
		if u.Live(now) != nil {
			return fmt.Errorf("gateway: unlock %s is not live: %w", u.ID, model.ErrConflict)
		}
		if u.LastUsedAt == nil || now.After(*u.LastUsedAt) {
			u.LastUsedAt = &now
		}
		return nil
	})
	if err != nil && !errors.Is(err, model.ErrConflict) {
		g.log.Error("gateway: could not count a change as use of its unlock", "unlock", id, "err", err)
	}
}

// lapseChanges ends every change still waiting for the technician under a
// grant that has ended. No release can run under that grant any more, so its
// card must not sit in the companion waiting for an approval that could only
// be refused.
func (g *Gateway) lapseChanges(ctx context.Context, a model.AccessRequest, reason string) {
	if g.approvals == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	open, err := g.approvals.ChangeApprovals(ctx, a.Technician, g.now())
	if err != nil {
		g.log.Error("gateway: could not list the changes of an ended grant", "access", a.ID, "err", err)
		return
	}
	why := "its access grant ended"
	if reason != "" {
		why += " (" + reason + ")"
	}
	for _, c := range open {
		if c.AccessID != a.ID || c.State != model.ChangeAwaiting {
			continue
		}
		if _, err := g.settleChange(ctx, c.ID, model.ChangeExpired, func(x *model.ChangeApproval) error {
			x.Reason = why
			return nil
		}); err != nil && !errors.Is(err, model.ErrConflict) {
			g.log.Error("gateway: could not lapse a change of an ended grant", "approval", c.ID, "err", err)
		}
	}
}

// rowCaller is who a transition the gateway makes outside any MCP call is
// recorded as: the technician and session the request belongs to.
func rowCaller(a model.AccessRequest) caller {
	return caller{session: model.Session{ID: a.Session, Tech: a.Technician}}
}
