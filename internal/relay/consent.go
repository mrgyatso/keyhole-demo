package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// consentTimeout bounds one endpoint consent transition: the durable write
// and the audit entry that must accompany it.
const consentTimeout = 15 * time.Second

// maxCapabilityToken bounds a grant ID or nonce the relay will store.
const maxCapabilityToken = 128

// ConsentRefusedTool is the audit tool name of an endpoint consent event the
// relay turned down. Args carries what the event claimed; ErrorMessage says
// why it was refused.
const ConsentRefusedTool = "access.refused"

// refusal is why the relay turned an endpoint consent event down. Every
// refusal is audited.
type refusal string

func (r refusal) Error() string { return string(r) }

// noSuchRequest is the refusal for an access ID this device has no request
// under. A request that exists but belongs to another client or device gets
// the same answer, so an event cannot probe for other tenants' requests.
const noSuchRequest = refusal("this device has no such access request")

// errLate is a waiting update that arrived after the request was decided. It
// carries no authority and changes nothing, so it is dropped quietly.
var errLate = errors.New("late waiting update")

// handleConsent records one endpoint consent transition. Consent is
// asynchronous — the endpoint acks the request and a person decides minutes
// later — so this is the path by which a decision becomes durable.
//
// The subject names the device, and NATS permissions let a device publish
// only its own subjects, so the subject's client and device are the only
// identity the relay believes. The payload must agree with them, and with the
// stored request in every binding, or the event is refused. Every refusal is
// audited in the chain of the client whose device sent it, as every applied
// transition is.
func (m *ConnManager) handleConsent(client, device string, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), consentTimeout)
	defer cancel()
	if len(data) > maxEventBytes {
		m.refuseConsent(ctx, client, device, proto.ConsentEvent{}, nil, audit.ResultDenied,
			fmt.Sprintf("oversized consent event (%d bytes)", len(data)))
		return
	}
	var ev proto.ConsentEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		m.refuseConsent(ctx, client, device, proto.ConsentEvent{}, nil, audit.ResultDenied, "malformed consent event")
		return
	}
	if err := checkEnvelope(client, device, ev); err != nil {
		m.refuseConsent(ctx, client, device, ev, nil, audit.ResultDenied, err.Error())
		return
	}
	a, applied, err := m.applyConsent(ctx, client, device, ev)
	var why refusal
	switch {
	case errors.Is(err, errLate):
		m.log.Debug("late waiting update ignored", "client", client, "device", device, "access", ev.AccessID)
		return
	case errors.As(err, &why):
		m.refuseConsent(ctx, client, device, ev, owned(a, client, device), audit.ResultDenied, string(why))
		return
	case err != nil:
		m.log.Error("could not record endpoint consent", "client", client, "device", device,
			"access", ev.AccessID, "state", ev.State, "err", err)
		m.refuseConsent(ctx, client, device, ev, owned(a, client, device), audit.ResultError,
			"the relay could not record this consent event")
		return
	}
	for _, state := range applied {
		m.auditConsent(ctx, a, state, a.Reason)
		m.log.Info("endpoint consent", "client", client, "device", device, "access", a.ID,
			"state", state, "reason", a.Reason, "approver", a.Approver)
	}
}

// checkEnvelope holds the payload to the subject it arrived on, before the
// stored request is even looked at.
func checkEnvelope(client, device string, ev proto.ConsentEvent) error {
	switch {
	case ev.AccessID == "" || ev.State == "":
		return refusal("consent event names no access request or state")
	case ev.Client != client:
		return refusal("consent event names another client than the device that sent it")
	case ev.Device != device:
		return refusal("consent event names another device than the one that sent it")
	case !endpointState(ev.State):
		return refusal(fmt.Sprintf("an endpoint cannot report state %q", clip(ev.State)))
	case ev.Seq == 0 && (ev.State == proto.ConsentApproved || ev.State == proto.ConsentNarrowed || ev.State == proto.ConsentPaused):
		// Reductions may be unsequenced (a restarted service reports what it
		// dropped); anything that grants or resumes must be ordered.
		return refusal("a decision, pause or resume must carry a sequence number")
	}
	return nil
}

// endpointState reports whether an endpoint may report state. Only the
// gateway creates a request or marks it active or expired.
func endpointState(state string) bool {
	switch state {
	case proto.ConsentAwaiting, proto.ConsentApproved, proto.ConsentNarrowed,
		proto.ConsentPaused, proto.ConsentDenied, proto.ConsentTerminated:
		return true
	}
	return false
}

// applyConsent records one endpoint event in a single transaction. Every
// check runs against the row as stored, and an approval lands with its
// capability and, when narrowed, as its narrowed and approved transitions
// together, so no reader can observe a decision without its capability or a
// narrowed request that is not yet usable. It returns the stored row and the
// transitions applied, in order.
func (m *ConnManager) applyConsent(ctx context.Context, client, device string, ev proto.ConsentEvent) (model.AccessRequest, []string, error) {
	var goos string
	var unlock *model.Unlock
	if ev.State == proto.ConsentApproved || ev.State == proto.ConsentNarrowed {
		d, err := m.st.Device(ctx, device)
		switch {
		case errors.Is(err, model.ErrNotFound) || (err == nil && (d.Client != client || d.RevokedAt != nil)):
			return model.AccessRequest{}, nil, refusal("the device that sent this approval is not enrolled")
		case err != nil:
			return model.AccessRequest{}, nil, err
		}
		goos = d.OS
		// The technician unlock a grant rests on is read here, as the device
		// is, because the transaction below holds only the request. The
		// transaction checks it is still the request's unlock.
		if unlock, err = m.requestUnlock(ctx, client, device, ev.AccessID); err != nil {
			return model.AccessRequest{}, nil, err
		}
	}
	now := time.Now().UTC()
	var applied []string
	a, err := m.st.UpdateAccessTx(ctx, ev.AccessID, func(a *model.AccessRequest) error {
		applied = nil
		switch {
		case a.Client != client || a.Device != device:
			return noSuchRequest
		case ev.Technician != a.Technician:
			return refusal("consent event names another technician than the request")
		case ev.Seq > 0 && ev.Seq <= a.EventSeq:
			return refusal(fmt.Sprintf("consent event %d is not newer than event %d already recorded", ev.Seq, a.EventSeq))
		}
		// A waiting update only says why the endpoint is still waiting, e.g.
		// that nobody is signed in to show the request to.
		if ev.State == proto.ConsentAwaiting {
			if a.State != model.AccessAwaiting {
				return errLate
			}
			a.Reason, a.EventSeq = clip(ev.Reason), max(a.EventSeq, ev.Seq)
			return nil
		}
		steps, resume, err := consentSteps(a, ev, goos, unlock)
		if err != nil {
			return err
		}
		cur := a.State
		for _, s := range steps {
			if !model.AccessAdvance(cur, s) {
				return refusal(fmt.Sprintf("a request that is %s cannot become %s", cur, s))
			}
			cur = s
		}
		record(a, ev, resume, now)
		a.State, a.EventSeq = cur, max(a.EventSeq, ev.Seq)
		applied = steps
		return nil
	})
	if errors.Is(err, model.ErrNotFound) {
		err = noSuchRequest
	}
	return a, applied, err
}

// consentSteps checks an event against the stored request and returns the
// transitions it makes, and whether it resumes a paused grant. unlock is the
// technician unlock the request was made under, as read before the
// transaction, or nil.
func consentSteps(a *model.AccessRequest, ev proto.ConsentEvent, goos string, unlock *model.Unlock) (steps []string, resume bool, err error) {
	switch ev.State {
	case proto.ConsentApproved, proto.ConsentNarrowed:
		if a.State == model.AccessPaused {
			if err := checkResume(a, ev); err != nil {
				return nil, false, err
			}
			return []string{model.AccessApproved}, true, nil
		}
		if err := checkCapability(a, ev, goos); err != nil {
			return nil, false, err
		}
		if err := checkUnlock(a, ev, unlock); err != nil {
			return nil, false, err
		}
		// The relay labels the decision by what was granted, not by what the
		// event calls it: anything less than the whole request is narrowed.
		if !sameSet(ev.Capability.Paths, a.RequestedScope) || !sameSet(ev.Capability.Operations, a.RequestedOperations) {
			return []string{model.AccessNarrowed, model.AccessApproved}, false, nil
		}
		return []string{model.AccessApproved}, false, nil
	case proto.ConsentPaused, proto.ConsentDenied, proto.ConsentTerminated:
		return []string{ev.State}, false, nil
	}
	return nil, false, refusal(fmt.Sprintf("an endpoint cannot report state %q", clip(ev.State)))
}

// checkCapability re-checks every binding of a newly issued capability
// against the stored request. The endpoint's own copy is authoritative for
// what it will allow, but the relay stores and presents this one, so it must
// never hold a capability wider than, or bound elsewhere than, the request
// the technician made.
func checkCapability(a *model.AccessRequest, ev proto.ConsentEvent, goos string) error {
	c := ev.Capability
	switch {
	case c == nil:
		return refusal("approval carries no capability")
	case ev.Approver == "":
		return refusal("approval names no approver")
	case c.AccessID != a.ID:
		return refusal("capability is bound to another access request")
	case c.Client != a.Client:
		return refusal("capability is bound to another client")
	case c.Device != a.Device:
		return refusal("capability is bound to another device")
	case c.Technician != a.Technician:
		return refusal("capability is bound to another technician")
	case c.GrantID == "" || c.Nonce == "" || len(c.GrantID) > maxCapabilityToken || len(c.Nonce) > maxCapabilityToken:
		return refusal("capability has no usable grant ID or nonce")
	case c.PolicyVersion != a.PolicyVersion:
		return refusal("capability names another policy version")
	case c.IssuedAt.IsZero() || !c.IssuedAt.Before(c.ExpiresAt):
		return refusal("capability has no valid lifetime")
	case c.ExpiresAt.After(a.ExpiresAt):
		return refusal("capability outlives the request")
	case c.IdleTimeout != a.IdleTimeout:
		return refusal("capability changes the idle timeout")
	case len(c.Operations) == 0 || len(c.Paths) == 0:
		return refusal("capability grants nothing")
	case !slices.Equal(c.Operations, ev.Operations) || !slices.Equal(c.Paths, ev.Paths):
		return refusal("capability and the scope the event reports disagree")
	}
	for _, op := range c.Operations {
		if !slices.Contains(a.RequestedOperations, op) {
			return refusal(fmt.Sprintf("capability grants operation %q, which was not requested", clip(op)))
		}
	}
	requested := make([]proto.AllowRule, len(a.RequestedScope))
	for i, p := range a.RequestedScope {
		requested[i] = proto.AllowRule{Path: p}
	}
	for _, p := range c.Paths {
		if slices.Contains(a.RequestedScope, p) {
			continue
		}
		// The same rule the endpoint applies: a granted path must lie inside
		// a requested one, with the device's own path syntax.
		if _, _, ok := policy.MatchAllow(goos, requested, p, true); !ok {
			return refusal(fmt.Sprintf("capability grants path %q, which is outside the request", clip(p)))
		}
	}
	return nil
}

// requestUnlock returns the technician unlock the named request was made
// under, when it is this device's own request and has one, and nil otherwise.
// The transaction answers a request that is missing or someone else's.
func (m *ConnManager) requestUnlock(ctx context.Context, client, device, accessID string) (*model.Unlock, error) {
	a, err := m.st.Access(ctx, accessID)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case a.Client != client || a.Device != device || a.Unlock == "":
		return nil, nil
	}
	u, err := m.st.Unlock(ctx, a.Unlock)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &u, nil
}

// checkUnlock holds a new grant to the technician unlock its request was made
// under (Slice 6). The grant must name exactly that unlock and say, as the
// request does, whether the person at the machine approved as well: the
// endpoint compares both on every call, and a request made without an unlock
// must never hold a grant that claims one. Where the unlock alone approved,
// the approver must be that unlock's signed approval and the unlock must still
// be active, so an endpoint cannot approve a request on an unlock the
// technician never gave or has since ended.
func checkUnlock(a *model.AccessRequest, ev proto.ConsentEvent, u *model.Unlock) error {
	c := ev.Capability
	switch {
	case a.Unlock == "" && c.Unlock != "":
		return refusal("capability claims a technician unlock, but the request was not made under one")
	case c.Unlock != a.Unlock:
		return refusal("capability names another unlock than the request")
	case c.EndpointConsent != a.EndpointConsent:
		return refusal("capability disagrees with the request about endpoint consent")
	case a.Unlock == "" || a.EndpointConsent:
		// The person at the machine approved, as in Slice 3, and the approver
		// named is theirs.
		return nil
	case u == nil || u.ID != a.Unlock || u.Technician != a.Technician || u.Client != a.Client:
		return refusal("the technician unlock the request was made under is unknown")
	case u.State != model.UnlockActive:
		return refusal(fmt.Sprintf("the technician unlock the request was made under is %s, not active", u.State))
	}
	signed, err := u.SignedApproval()
	if err != nil || ev.Approver != signed.ApproverLabel() {
		return refusal("approval names another approver than the technician who unlocked the client")
	}
	return nil
}

// checkResume allows a paused grant back only with the capability it was
// granted. A resume changes nothing about the grant: not its scope, its
// lifetime, its approver or the unlock it rests on.
func checkResume(a *model.AccessRequest, ev proto.ConsentEvent) error {
	c := ev.Capability
	switch {
	case a.GrantID == "" || a.Nonce == "" || a.DecidedAt == nil:
		return refusal("nothing was granted, so there is nothing to resume")
	case c == nil || c.AccessID != a.ID || c.GrantID != a.GrantID || c.Nonce != a.Nonce ||
		c.Client != a.Client || c.Device != a.Device || c.Technician != a.Technician ||
		c.Unlock != a.Unlock || c.EndpointConsent != a.EndpointConsent:
		return refusal("a resumed grant must carry the capability it was granted")
	}
	return nil
}

// record copies what an accepted event says into the stored request.
func record(a *model.AccessRequest, ev proto.ConsentEvent, resume bool, now time.Time) {
	reason := clip(ev.Reason)
	switch ev.State {
	case proto.ConsentApproved, proto.ConsentNarrowed:
		if resume {
			a.PausedAt, a.Reason = nil, reason
			return
		}
		c := ev.Capability
		issued := c.IssuedAt.UTC()
		a.DecidedAt, a.Approver, a.ApproverSession, a.Reason = &issued, clip(ev.Approver), clip(ev.ApproverSession), reason
		a.EffectiveScope, a.EffectiveOperations = slices.Clone(c.Paths), slices.Clone(c.Operations)
		a.GrantID, a.Nonce, a.ExpiresAt, a.PausedAt = c.GrantID, c.Nonce, c.ExpiresAt.UTC(), nil
	case proto.ConsentPaused:
		paused := now
		a.PausedAt, a.Reason = &paused, reason
	case proto.ConsentDenied:
		if a.DecidedAt == nil {
			decided := now
			a.DecidedAt, a.Approver, a.ApproverSession = &decided, clip(ev.Approver), clip(ev.ApproverSession)
		} else {
			// Refusing a grant already made ends it; who made it stays on record.
			ended := now
			a.TerminatedAt = &ended
		}
		a.Reason = reason
	case proto.ConsentTerminated:
		ended := now
		a.TerminatedAt, a.Reason = &ended, reason
	}
}

// owned returns a when it is this device's own request, so that a refusal
// names the technician and session involved, and nil otherwise, so that a
// refusal never copies another tenant's details into this client's chain.
func owned(a model.AccessRequest, client, device string) *model.AccessRequest {
	if a.ID == "" || a.Client != client || a.Device != device {
		return nil
	}
	return &a
}

// refuseConsent records an endpoint consent event the relay did not apply,
// in the chain of the client whose device sent it.
func (m *ConnManager) refuseConsent(ctx context.Context, client, device string, ev proto.ConsentEvent, a *model.AccessRequest, result, why string) {
	m.log.Warn("endpoint consent event refused", "client", client, "device", device,
		"access", clip(ev.AccessID), "state", clip(ev.State), "seq", ev.Seq, "reason", why)
	if m.audit == nil {
		return
	}
	args, _ := json.Marshal(struct {
		Source          string `json:"source"`
		State           string `json:"state,omitempty"`
		Seq             uint64 `json:"seq,omitempty"`
		Client          string `json:"client,omitempty"`
		Device          string `json:"device,omitempty"`
		Approver        string `json:"approver,omitempty"`
		ApproverSession string `json:"approver_session,omitempty"`
	}{"endpoint", clip(ev.State), ev.Seq, clip(ev.Client), clip(ev.Device), clip(ev.Approver), clip(ev.ApproverSession)})
	code := proto.ErrGrantInvalid
	if result == audit.ResultError {
		code = proto.ErrInternal
	}
	e := audit.Entry{Kind: audit.KindConsent, Client: client, DeviceID: device, RequestID: clip(ev.AccessID),
		Tool: ConsentRefusedTool, Args: args, Result: result, ErrorCode: code, ErrorMessage: why}
	if a != nil {
		e.Tech, e.SessionID = a.Technician, a.Session
	}
	if err := m.audit.Append(ctx, &e); err != nil {
		m.log.Error("could not audit a refused consent event", "client", client, "device", device, "err", err)
	}
}

// auditConsent records an endpoint-initiated transition in the client's
// chain, in the same shape the gateway uses for the transitions it makes.
func (m *ConnManager) auditConsent(ctx context.Context, a model.AccessRequest, state, reason string) {
	if m.audit == nil {
		return
	}
	result := audit.ResultOK
	if state == model.AccessDenied || state == model.AccessPaused || state == model.AccessTerminated {
		result = audit.ResultDenied
	}
	args, _ := json.Marshal(struct {
		Approver string `json:"approver,omitempty"`
		Session  string `json:"approver_session,omitempty"`
		Source   string `json:"source"`
	}{a.Approver, a.ApproverSession, "endpoint"})
	e := audit.Entry{Kind: audit.KindConsent, Client: a.Client, DeviceID: a.Device, Tech: a.Technician,
		SessionID: a.Session, RequestID: a.ID, Tool: "access." + state, Args: args, Result: result, ErrorMessage: reason}
	if err := m.audit.Append(ctx, &e); err != nil {
		m.log.Error("could not audit endpoint consent", "client", a.Client, "access", a.ID, "state", state, "err", err)
	}
}

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	for _, s := range b {
		if !slices.Contains(a, s) {
			return false
		}
	}
	return true
}
