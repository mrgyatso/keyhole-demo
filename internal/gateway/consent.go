package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func (g *Gateway) requestAccess(ctx context.Context, c caller, in RequestAccessInput, input json.RawMessage) *mcp.CallToolResult {
	if g.access == nil {
		return toolError(proto.ErrInternal, "consented access store is unavailable")
	}
	if g.technicianApproval() {
		return g.requestUnlockedAccess(ctx, c, in, input)
	}
	client, ce := g.admitClient(ctx, c, in.Client)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	dev, ce := g.resolveDevice(ctx, client.Slug, in.Device)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	if in.Purpose == "" || len(in.Paths) == 0 || in.DurationMinutes < 1 || in.DurationMinutes > 60 || in.IdleMinutes > in.DurationMinutes {
		return toolError(proto.ErrBadRequest, "purpose, at least one path, and duration_minutes from 1 to 60 are required")
	}
	ops, err := changeOperations(in.Operations)
	if err != nil {
		return toolError(proto.ErrBadRequest, err.Error())
	}
	now := g.now().UTC()
	idle := time.Duration(in.IdleMinutes) * time.Minute
	if idle <= 0 {
		idle = min(10*time.Minute, time.Duration(in.DurationMinutes)*time.Minute)
	}
	deadline := now.Add(proto.ConsentTimeout)
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: client.Slug, Device: dev.ID, Technician: c.session.Tech, Session: c.session.ID, Purpose: in.Purpose, State: model.AccessRequested, RequestedScope: slices.Clone(in.Paths), RequestedOperations: ops, RequestedAt: now, ExpiresAt: now.Add(time.Duration(in.DurationMinutes) * time.Minute), IdleTimeout: idle, PolicyVersion: client.Policy.Version, ConsentDeadline: &deadline}
	if err := g.access.CreateAccess(ctx, a); err != nil {
		return toolError(proto.ErrInternal, "could not store access request")
	}
	if err := g.auditConsent(ctx, c, a, model.AccessRequested, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request was stored but could not be audited")
	}
	awaiting, err := g.advance(ctx, a.ID, model.AccessAwaiting, nil)
	if err != nil {
		return toolError(proto.ErrInternal, "could not await endpoint consent")
	}
	a = awaiting
	if err := g.auditConsent(ctx, c, a, model.AccessAwaiting, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request could not be audited")
	}
	cr := proto.ConsentRequest{AccessID: a.ID, Client: a.Client, Device: a.Device, Technician: a.Technician, Purpose: a.Purpose, Operations: a.RequestedOperations, Paths: a.RequestedScope, Duration: a.ExpiresAt.Sub(now), ExpiresAt: a.ExpiresAt, IdleTimeout: a.IdleTimeout, PolicyVersion: a.PolicyVersion}
	b, _ := json.Marshal(cr)
	req := proto.Request{V: proto.Version, ID: model.NewID(model.PrefixRequest), Op: proto.OpRequestAccess, Args: b, Policy: client.Policy.For(dev.OS), Caller: proto.Caller{Tech: c.session.Tech, Session: c.session.ID}, Deadline: time.Now().Add(g.timeout)}
	resp, ce := g.rpc(ctx, client.Slug, dev.ID, req)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	if !resp.OK {
		ce = agentError(resp.Error)
		return toolError(ce.code, ce.msg)
	}
	if ce = checkIntegrity(resp); ce != nil {
		return toolError(ce.code, ce.msg)
	}
	// The endpoint only acknowledges here. A person needs minutes, so the
	// decision arrives later on proto.EvtConsent and the relay stores it; the
	// technician polls access_status for the durable state.
	var d proto.ConsentDecision
	if err := json.Unmarshal(resp.Result, &d); err != nil {
		return toolError(proto.ErrInternal, "malformed consent decision")
	}
	if d.State != proto.ConsentAwaiting {
		return toolError(proto.ErrInternal, "the endpoint did not accept the access request for consent")
	}
	raw, _ := json.Marshal(a)
	return jsonResult(raw)
}

// ----- request_access under technician approval (Slice 6) -----

// readOperations is what an access request asks for under technician approval
// when it names none: every read and no change, so that a change always needs
// a request that says so.
var readOperations = []string{proto.OpReadFile, proto.OpListDir, proto.OpStat, proto.OpSearchFiles, proto.OpGrep, proto.OpHashFile,
	proto.OpListPrinters}

// A managed endpoint approves a request that carries the technician's unlock
// itself, within a second or so, so request_access waits up to decisionWait
// for that decision, looking every decisionPoll, and the model can use the
// grant at once instead of polling. Tests shorten them.
var (
	decisionWait = 5 * time.Second
	decisionPoll = 100 * time.Millisecond
)

// pendingUnlocks serialises finding or creating a technician's pending unlock
// of a client, so that requests the model sends in parallel for several
// machines of one client share one unlock card instead of making one each.
var pendingUnlocks sync.Mutex

// unlockRequest is one validated request_access call under technician
// approval.
type unlockRequest struct {
	client   model.Client
	dev      model.Device
	purpose  string
	paths    []string
	ops      []string
	duration time.Duration // zero: as long as the unlock lasts
	idle     time.Duration // an unlock this request creates idles after it; zero is the default
}

// requestUnlockedAccess is request_access under technician approval. Under a
// live unlock of the client the request goes to the endpoint at once with the
// technician's signed approval; otherwise it waits, as awaiting_unlock, for
// the technician to approve an unlock in the companion. Legacy client-bound
// sessions take the same path, as their session's technician.
func (g *Gateway) requestUnlockedAccess(ctx context.Context, c caller, in RequestAccessInput, input json.RawMessage) *mcp.CallToolResult {
	client, ce := g.admitClient(ctx, c, in.Client)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	dev, ce := g.resolveDevice(ctx, client.Slug, in.Device)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	now := g.now().UTC()
	switch {
	case strings.TrimSpace(in.Purpose) == "":
		return toolError(proto.ErrBadRequest, "purpose is required: say what the access is for, such as the ticket, so the technician recognises it")
	case in.DurationMinutes < 0 || in.DurationMinutes > 60:
		return toolError(proto.ErrBadRequest, "duration_minutes is optional and from 1 to 60")
	case in.IdleMinutes < 0 || in.IdleMinutes > 60:
		return toolError(proto.ErrBadRequest, "idle_minutes is optional and from 1 to 60")
	case dev.RevokedAt != nil || dev.Expired(now):
		// Asking the technician to unlock a client for a machine that can
		// never be reached again would only waste the approval.
		return toolError(proto.ErrDeviceRevoked, deviceLabel(dev)+" is no longer enrolled; call list_devices to see this client's machines")
	}
	r := unlockRequest{client: client, dev: dev, purpose: strings.TrimSpace(in.Purpose), ops: slices.Clone(readOperations),
		duration: time.Duration(in.DurationMinutes) * time.Minute, idle: time.Duration(in.IdleMinutes) * time.Minute}
	if len(in.Operations) > 0 {
		ops, err := changeOperations(in.Operations)
		if err != nil {
			return toolError(proto.ErrBadRequest, err.Error())
		}
		r.ops = ops
	}
	if r.paths, ce = requestPaths(dev.OS, client.Policy.For(dev.OS).Allow, in.Paths); ce != nil {
		return toolError(ce.code, ce.msg)
	}

	u, err := g.approvals.UnlockFor(ctx, c.session.Tech, client.Slug, model.UnlockActive)
	switch {
	case err == nil && u.Live(now) == nil:
		return g.requestUnderUnlock(ctx, c, r, u, now, input)
	case err == nil:
		// Active in the store but past its own deadlines: end it now rather
		// than wait for the reconcile loop, so this request waits for a new
		// unlock instead of beside a dead one.
		g.expireUnlock(ctx, u.ID, now)
	case !errors.Is(err, model.ErrNotFound):
		g.log.Error("gateway: unlock lookup failed", "technician", c.session.Tech, "client", client.Slug, "err", err)
		return toolError(proto.ErrInternal, "could not look up the client's unlock")
	}
	return g.requestAwaitingUnlock(ctx, c, r, now, input)
}

// requestUnderUnlock stores a request made under a live unlock, forwards it to
// its endpoint with the unlock's signed approval, and waits briefly for the
// endpoint's decision. The grant can never outlive the unlock.
func (g *Gateway) requestUnderUnlock(ctx context.Context, c caller, r unlockRequest, u model.Unlock, now time.Time, input json.RawMessage) *mcp.CallToolResult {
	signed, err := u.SignedApproval()
	if err != nil {
		g.log.Error("gateway: an active unlock carries no approval", "unlock", u.ID, "err", err)
		return toolError(proto.ErrInternal, "the client's unlock carries no approval")
	}
	expires := *u.ExpiresAt
	if r.duration > 0 && now.Add(r.duration).Before(expires) {
		expires = now.Add(r.duration)
	}
	deadline := now.Add(proto.ConsentTimeout)
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: r.client.Slug, Device: r.dev.ID, Technician: c.session.Tech,
		Session: c.session.ID, Purpose: r.purpose, State: model.AccessRequested, RequestedScope: r.paths, RequestedOperations: r.ops,
		RequestedAt: now, ExpiresAt: expires, IdleTimeout: grantIdle(u, expires.Sub(now)), PolicyVersion: r.client.Policy.Version,
		ConsentDeadline: &deadline, Unlock: u.ID, EndpointConsent: r.client.Policy.EndpointConsent}
	if err := g.access.CreateAccess(ctx, a); err != nil {
		return toolError(proto.ErrInternal, "could not store access request")
	}
	if err := g.auditConsent(ctx, c, a, model.AccessRequested, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request was stored but could not be audited")
	}
	a, err = g.advance(ctx, a.ID, model.AccessAwaiting, nil)
	if err != nil {
		return toolError(proto.ErrInternal, "could not forward the access request")
	}
	if err := g.auditConsent(ctx, c, a, model.AccessAwaiting, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request could not be audited")
	}
	if ce := g.forwardAccess(ctx, c, r.client, r.dev, a, signed, input); ce != nil {
		return toolError(ce.code, ce.msg)
	}
	if !a.EndpointConsent {
		a = g.awaitDecision(ctx, a)
	}
	return g.answerAccess(a)
}

// requestAwaitingUnlock stores a request that waits for the technician to
// unlock its client, on the technician's pending unlock of that client or a
// new one, and answers with the unlock card's link.
func (g *Gateway) requestAwaitingUnlock(ctx context.Context, c caller, r unlockRequest, now time.Time, input json.RawMessage) *mcp.CallToolResult {
	u, ce := g.pendingUnlock(ctx, c, r, now)
	if ce != nil {
		return toolError(ce.code, ce.msg)
	}
	d := r.duration
	if d == 0 || d > u.Duration {
		d = u.Duration // the unlock lasts no longer once approved
	}
	deadline := u.Deadline
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: r.client.Slug, Device: r.dev.ID, Technician: c.session.Tech,
		Session: c.session.ID, Purpose: r.purpose, State: model.AccessRequested, RequestedScope: r.paths, RequestedOperations: r.ops,
		RequestedAt: now, ExpiresAt: now.Add(d), IdleTimeout: grantIdle(u, d), PolicyVersion: r.client.Policy.Version,
		ConsentDeadline: &deadline, Unlock: u.ID, EndpointConsent: r.client.Policy.EndpointConsent}
	if err := g.access.CreateAccess(ctx, a); err != nil {
		return toolError(proto.ErrInternal, "could not store access request")
	}
	if err := g.auditConsent(ctx, c, a, model.AccessRequested, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request was stored but could not be audited")
	}
	a, err := g.advance(ctx, a.ID, model.AccessAwaitingUnlock, nil)
	if err != nil {
		return toolError(proto.ErrInternal, "could not store the access request as waiting for the unlock")
	}
	if err := g.auditConsent(ctx, c, a, model.AccessAwaitingUnlock, input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "access request could not be audited")
	}
	// The technician may have approved the unlock between finding it pending
	// and storing this request, after the approval had already forwarded the
	// requests it found waiting. Forwarding it here as well closes that gap;
	// whichever of the two moves the request first wins, and the other finds
	// it no longer waiting.
	if cur, err := g.approvals.Unlock(ctx, u.ID); err == nil && cur.State == model.UnlockActive && cur.Live(now) == nil {
		if signed, err := cur.SignedApproval(); err == nil {
			a = g.forwardWaiting(ctx, cur, signed, a)
			if a.State == model.AccessAwaiting && !a.EndpointConsent {
				a = g.awaitDecision(ctx, a)
			}
		}
	}
	return g.answerAccess(a)
}

// pendingUnlock returns the technician's unlock of the client that is waiting
// for approval, or creates one. One past its deadline is ended first, so a
// request never waits on a card nobody can approve any more.
func (g *Gateway) pendingUnlock(ctx context.Context, c caller, r unlockRequest, now time.Time) (model.Unlock, *callError) {
	pendingUnlocks.Lock()
	defer pendingUnlocks.Unlock()
	u, err := g.approvals.UnlockFor(ctx, c.session.Tech, r.client.Slug, model.UnlockAwaiting)
	if err == nil {
		if state, _ := u.Due(now); state == "" {
			return u, nil
		}
		g.expireUnlock(ctx, u.ID, now)
	} else if !errors.Is(err, model.ErrNotFound) {
		g.log.Error("gateway: unlock lookup failed", "technician", c.session.Tech, "client", r.client.Slug, "err", err)
		return model.Unlock{}, failed(proto.ErrInternal, "could not look up the client's unlock")
	}
	d := r.duration
	if d == 0 {
		d = model.MaxUnlockDuration
	}
	idle := model.DefaultUnlockIdle
	if r.idle > 0 {
		idle = r.idle
	}
	u = model.Unlock{ID: model.NewID(model.PrefixUnlock), Technician: c.session.Tech, Client: r.client.Slug, Session: c.session.ID,
		Purpose: r.purpose, State: model.UnlockAwaiting, Duration: min(d, model.MaxUnlockDuration), IdleTimeout: idle,
		RequestedAt: now, Deadline: now.Add(model.UnlockApprovalWindow)}
	if err := g.approvals.CreateUnlock(ctx, u); err != nil {
		g.log.Error("gateway: could not store an unlock", "technician", c.session.Tech, "client", r.client.Slug, "err", err)
		return model.Unlock{}, failed(proto.ErrInternal, "could not store the unlock request")
	}
	if err := g.auditUnlock(ctx, u); err != nil {
		return model.Unlock{}, failed(proto.ErrAuditFailed, "the unlock request was stored but could not be audited")
	}
	return u, nil
}

// requestPaths is the scope an access request asks for under technician
// approval: the paths given, each of which must overlap one of the client's
// allow rules for the device's OS, or, when none are given, the path of every
// rule. The endpoint narrows what it grants to the policy as well; this
// refuses at the relay a path that could never grant anything.
func requestPaths(goos string, rules []proto.AllowRule, asked []string) ([]string, *callError) {
	var roots []string
	for _, r := range rules {
		if !slices.Contains(roots, r.Path) {
			roots = append(roots, r.Path)
		}
	}
	if len(roots) == 0 {
		return nil, denied(proto.ErrNotAllowed, "this client's policy allows no location on "+goos+" machines")
	}
	if len(asked) == 0 {
		return roots, nil
	}
	var out []string
	for _, p := range asked {
		p = strings.TrimSpace(p)
		if !overlapsAllow(goos, rules, p) {
			return nil, denied(proto.ErrNotAllowed, fmt.Sprintf("%q is outside every location this client's policy allows on %s machines; ask for one of: %s",
				p, goos, strings.Join(roots, "; ")))
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// grantIdle is the idle timeout of a grant made under unlock u that lasts
// lifetime. The relay ends the unlock itself after u.IdleTimeout without use,
// and counts the change gate's steps as use. The endpoint enforces the
// grant's own idle timeout and sees nothing of a change waiting for the
// technician's approval, so the grant idles only after the unlock's idle
// timeout plus a whole approval window; otherwise it would refuse a change the
// technician approved in time. An unlock that never idles makes a grant that
// never does.
func grantIdle(u model.Unlock, lifetime time.Duration) time.Duration {
	if u.IdleTimeout <= 0 {
		return 0
	}
	return min(u.IdleTimeout+model.ChangeApprovalWindow, lifetime)
}

// overlapsAllow reports whether p lies inside one of rules or contains one,
// matched segment by segment in the device's own path syntax. These are the
// two cases the endpoint keeps when it narrows a grant to its policy; a path
// that is neither would be narrowed to nothing.
func overlapsAllow(goos string, rules []proto.AllowRule, p string) bool {
	if _, _, ok := policy.MatchAllow(goos, rules, p, true); ok {
		return true
	}
	within := []proto.AllowRule{{Path: p}}
	for _, r := range rules {
		if _, _, ok := policy.MatchAllow(goos, within, r.Path, true); ok {
			return true
		}
	}
	return false
}

// awaitDecision waits briefly for the endpoint's decision on a request it has
// just acknowledged, which the relay records as it arrives, and returns the
// request as it then stands.
func (g *Gateway) awaitDecision(ctx context.Context, a model.AccessRequest) model.AccessRequest {
	wait := time.NewTimer(decisionWait)
	defer wait.Stop()
	tick := time.NewTicker(decisionPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return a
		case <-wait.C:
			return a
		case <-tick.C:
		}
		cur, err := g.access.Access(ctx, a.ID)
		if err != nil {
			g.log.Error("gateway: could not read an access request back", "access", a.ID, "err", err)
			return a
		}
		if a = cur; a.State != model.AccessAwaiting {
			return a
		}
	}
}

// accessAnswer is what request_access and access_status return under
// technician approval: the stored request and, while it waits, what it waits
// for and what the model should do next. The capability never appears.
type accessAnswer struct {
	model.AccessRequest
	AccessID string `json:"access_id"`
	UnlockID string `json:"unlock_id,omitempty"`
	Link     string `json:"link,omitempty"` // the unlock card in the companion
	Next     string `json:"next,omitempty"`
}

func (g *Gateway) answerAccess(a model.AccessRequest) *mcp.CallToolResult {
	ans := accessAnswer{AccessRequest: a, AccessID: a.ID, UnlockID: a.Unlock}
	switch a.State {
	case model.AccessRequested, model.AccessAwaitingUnlock:
		ans.Link = g.companionLink("u", a.Unlock)
		where := "in the Keyhole companion"
		if ans.Link != "" {
			where += " (" + ans.Link + ")"
		}
		ans.Next = "This client is locked. Ask the technician to approve the unlock " + where +
			" with their passkey, then poll access_status with this access_id until it is approved. Nothing you can call approves it."
	case model.AccessAwaiting:
		ans.Next = "The request is with the endpoint, which has not recorded its decision yet; poll access_status in a few seconds."
		if a.EndpointConsent {
			ans.Next = "The technician's unlock is attached, and this client's policy also asks the person at the machine, who is deciding now; poll access_status until the request leaves awaiting_consent."
		}
	case model.AccessApproved, model.AccessActive:
		ans.Next = "Approved. Pass this access_id to the read tools. The grant ends at expires_at, when the technician's unlock of this client ends, or with end_access."
	case model.AccessPaused:
		ans.Next = "The grant is paused at the machine; poll access_status."
	default:
		ans.Next = "This request has ended"
		if a.Reason != "" {
			ans.Next += " (" + a.Reason + ")"
		}
		ans.Next += ". Call request_access again if the work needs access."
	}
	raw, _ := json.Marshal(ans)
	return jsonResult(raw)
}

// advance moves one stored access request to state, applying update to the
// row as it is stored now rather than to a copy read earlier. The relay
// records endpoint decisions concurrently, so a gateway write built from a
// stale copy could otherwise revive a request the endpoint user had already
// paused or ended. It returns an error wrapping model.ErrConflict, and
// changes nothing, when the stored row cannot make that move.
func (g *Gateway) advance(ctx context.Context, id, state string, update func(*model.AccessRequest)) (model.AccessRequest, error) {
	return g.access.UpdateAccessTx(ctx, id, func(a *model.AccessRequest) error {
		if !model.AccessAdvance(a.State, state) {
			return fmt.Errorf("access %s is %s and cannot become %s: %w", a.ID, a.State, state, model.ErrConflict)
		}
		a.State = state
		if update != nil {
			update(a)
		}
		return nil
	})
}

// terminate ends one stored access request at the relay, as of ended, with
// reason if one is given. sent reports whether its endpoint has seen the
// request, and so has something to revoke: a request still waiting for a
// technician unlock never left the relay.
func (g *Gateway) terminate(ctx context.Context, id, reason string, ended time.Time) (stored model.AccessRequest, sent bool, err error) {
	stored, err = g.access.UpdateAccessTx(ctx, id, func(a *model.AccessRequest) error {
		if !model.AccessAdvance(a.State, model.AccessTerminated) {
			return fmt.Errorf("access %s is %s and cannot become %s: %w", a.ID, a.State, model.AccessTerminated, model.ErrConflict)
		}
		sent = a.State != model.AccessAwaitingUnlock
		a.State, a.TerminatedAt = model.AccessTerminated, &ended
		if reason != "" {
			a.Reason = reason
		}
		return nil
	})
	return stored, sent, err
}

// due reports the state the relay's own deadlines put a request in at now,
// and why, or "" when none applies: a request whose lifetime has passed,
// decided or not, has expired, and one nobody decided within
// proto.ConsentTimeout is refused.
func due(a model.AccessRequest, now time.Time) (state, reason string) {
	switch {
	case model.AccessTerminal(a.State):
		return "", ""
	case !now.Before(a.ExpiresAt):
		return model.AccessExpired, "expired"
	case a.ConsentOverdue(now):
		return model.AccessDenied, proto.ReasonTimeout
	}
	return "", ""
}

// refresh applies the deadlines the relay enforces for itself, independently
// of the endpoint (see due); the endpoint enforces both again and its
// decision is final. The move is made against the stored row, so a decision
// the endpoint recorded after a was read is never overwritten by a deadline
// it beat. If the store cannot be written the request is still refused: the
// caller gets the due state, unstored.
func (g *Gateway) refresh(ctx context.Context, c caller, a model.AccessRequest, input json.RawMessage) model.AccessRequest {
	now := g.now()
	if state, _ := due(a, now); state == "" {
		return a
	}
	var reason string
	stored, err := g.access.UpdateAccessTx(ctx, a.ID, func(cur *model.AccessRequest) error {
		var state string
		state, reason = due(*cur, now)
		if state == "" || !model.AccessAdvance(cur.State, state) {
			return fmt.Errorf("access %s: no deadline is due: %w", cur.ID, model.ErrConflict)
		}
		if state == model.AccessDenied {
			decided := now.UTC()
			cur.Reason, cur.DecidedAt = reason, &decided
		}
		cur.State = state
		return nil
	})
	switch {
	case errors.Is(err, model.ErrConflict):
		return stored
	case err != nil:
		g.log.Error("gateway: could not store an expired or overdue access request", "access", a.ID, "err", err)
		a.State, _ = due(a, now)
		return a
	}
	if err := g.auditConsent(ctx, c, stored, stored.State, input, audit.ResultDenied, reason); err != nil {
		g.log.Error("gateway: could not audit an expired or overdue access request", "access", a.ID, "err", err)
	}
	return stored
}

// activate records the first successful call under an approved grant. It
// moves the stored row, not the copy the call was admitted with, so a pause
// or termination the endpoint recorded while the call was in flight stands.
// The endpoint authorised that call itself when it ran it; only the
// activation is moot.
func (g *Gateway) activate(ctx context.Context, c caller, a model.AccessRequest, input json.RawMessage) *callError {
	stored, err := g.advance(ctx, a.ID, model.AccessActive, nil)
	switch {
	case errors.Is(err, model.ErrConflict):
		g.log.Info("gateway: grant changed while a call was in flight; not marked active", "access", a.ID, "state", stored.State)
		return nil
	case err != nil:
		return failed(proto.ErrInternal, "could not activate access grant")
	}
	if err := g.auditConsent(ctx, c, stored, model.AccessActive, input, audit.ResultOK, ""); err != nil {
		return failed(proto.ErrAuditFailed, "grant activation could not be audited")
	}
	return nil
}

func (g *Gateway) accessStatus(ctx context.Context, c caller, id string, input json.RawMessage) *mcp.CallToolResult {
	if g.access == nil {
		return toolError(proto.ErrInternal, "consented access store is unavailable")
	}
	a, err := g.access.Access(ctx, id)
	if err != nil || a.Technician != c.session.Tech || (!c.technician && a.Client != c.client.Slug) {
		return toolError(proto.ErrGrantInvalid, "access request not found")
	}
	if _, ce := g.admitClient(ctx, c, a.Client); ce != nil {
		return toolError(ce.code, ce.msg)
	}
	a = g.refresh(ctx, c, a, input)
	if err := g.auditConsent(ctx, c, a, "status", input, audit.ResultOK, ""); err != nil {
		return toolError(proto.ErrAuditFailed, "status could not be audited")
	}
	if g.technicianApproval() {
		return g.answerAccess(a)
	}
	raw, _ := json.Marshal(a)
	return jsonResult(raw)
}

func (g *Gateway) endAccess(ctx context.Context, c caller, id string, input json.RawMessage) *mcp.CallToolResult {
	if g.access == nil {
		return toolError(proto.ErrInternal, "consented access store is unavailable")
	}
	a, err := g.access.Access(ctx, id)
	if err != nil || a.Technician != c.session.Tech || (!c.technician && a.Client != c.client.Slug) {
		return toolError(proto.ErrGrantInvalid, "access request not found")
	}
	if _, ce := g.admitClient(ctx, c, a.Client); ce != nil {
		return toolError(ce.code, ce.msg)
	}
	// Reducing access is always possible: a pending or paused request can be
	// withdrawn too, and only a finished one has nothing left to end.
	a = g.refresh(ctx, c, a, input)
	if model.AccessTerminal(a.State) {
		return toolError(proto.ErrGrantInvalid, "access grant is already "+a.State)
	}
	stored, sent, err := g.terminate(ctx, a.ID, "", g.now().UTC())
	switch {
	case errors.Is(err, model.ErrConflict):
		// The endpoint finished it between the read above and this write.
		return toolError(proto.ErrGrantInvalid, "access grant is already "+stored.State)
	case err != nil:
		return toolError(proto.ErrInternal, "could not terminate access")
	}
	a = stored
	g.lapseChanges(ctx, a, "")
	var ce *callError
	if sent {
		ce = g.revokeAtEndpoint(ctx, a, proto.Caller{Tech: c.session.Tech, Session: c.session.ID})
	}
	result, reason := audit.ResultOK, ""
	if ce != nil {
		result, reason = audit.ResultError, ce.msg
	}
	if err := g.auditConsent(ctx, c, a, a.State, input, result, reason); err != nil {
		return toolError(proto.ErrAuditFailed, "termination was stored but could not be audited")
	}
	if ce != nil {
		return toolError(ce.code, "access is terminated at the gateway; endpoint revocation failed: "+ce.msg)
	}
	raw, _ := json.Marshal(a)
	return jsonResult(raw)
}

// revokeAtEndpoint tells the endpoint of a request the relay has just ended
// to drop its grant, or the pending request, now rather than at its expiry.
// The relay's own record is already final and refuses every further call;
// this is the endpoint doing its half. who is recorded in the endpoint's own
// audit mirror.
func (g *Gateway) revokeAtEndpoint(ctx context.Context, a model.AccessRequest, who proto.Caller) *callError {
	dev, ce := g.resolveDevice(ctx, a.Client, a.Device)
	if ce != nil {
		return ce
	}
	b, _ := json.Marshal(proto.EndAccessArgs{AccessID: a.ID, GrantID: a.GrantID, Nonce: a.Nonce})
	req := proto.Request{V: proto.Version, ID: model.NewID(model.PrefixRequest), Op: proto.OpEndAccess, Args: b, Caller: who, Deadline: time.Now().Add(g.timeout)}
	resp, ce := g.rpc(ctx, a.Client, dev.ID, req)
	if ce == nil && !resp.OK {
		ce = agentError(resp.Error)
	}
	return ce
}

func (g *Gateway) auditConsent(ctx context.Context, c caller, a model.AccessRequest, state string, args json.RawMessage, result, reason string) error {
	e := audit.Entry{Kind: audit.KindConsent, Client: a.Client, DeviceID: a.Device, Tech: c.session.Tech, SessionID: c.session.ID, RequestID: a.ID, Tool: "access." + state, Args: args, Result: result, ErrorMessage: reason}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := g.audit.Append(actx, &e); err != nil {
		return fmt.Errorf("audit consent: %w", err)
	}
	return nil
}
