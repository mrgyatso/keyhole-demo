package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// ConsentAdapter represents the local consent application. A human needs
// minutes, so Request starts one approval interaction and returns at once:
// the decision and every later transition of that grant (pause, resume, the
// user ending it) arrive on the returned channel, which the adapter closes
// when it has nothing more to say. A non-terminal update with State
// awaiting_consent carries why the request is still waiting, e.g.
// proto.ReasonNoUser while nobody is signed in to show it to.
//
// ctx is the life of the request: it ends when the runner is finished with
// the request for any reason, including ones the adapter did not report
// (the technician ended it, it expired, the endpoint's consent window closed
// on it). context.Cause(ctx) is then a proto.Reason* value saying why, so an
// adapter that shows requests to a person can close them truthfully.
type ConsentAdapter interface {
	Request(ctx context.Context, r proto.ConsentRequest) (<-chan proto.ConsentUpdate, error)
	// Activity shows one operation performed under a live grant to the
	// endpoint user. It must not block.
	Activity(proto.ConsentActivity)
}

// TestConsentAdapter is deterministic endpoint consent for automated tests.
// It answers inside Request, on a buffered channel, so the asynchronous
// endpoint path is exercised with a synchronous decision. Empty
// EffectivePaths/Operations retain the requested values.
type TestConsentAdapter struct {
	State, Approver, Reason             string
	EffectivePaths, EffectiveOperations []string
}

func (a TestConsentAdapter) Request(_ context.Context, r proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	state := a.State
	if state == "" {
		state = proto.ConsentApproved
	}
	paths := slices.Clone(a.EffectivePaths)
	if paths == nil {
		paths = slices.Clone(r.Paths)
	}
	ops := slices.Clone(a.EffectiveOperations)
	if ops == nil {
		ops = slices.Clone(r.Operations)
	}
	ch := make(chan proto.ConsentUpdate, 1)
	ch <- proto.ConsentUpdate{State: state, Approver: a.Approver, Reason: a.Reason, Paths: paths, Operations: ops, Final: true}
	close(ch)
	return ch, nil
}

func (TestConsentAdapter) Activity(proto.ConsentActivity) {}

// liveGrant is one access request this endpoint is holding: pending while
// the user decides, then the capability the user granted. The endpoint's
// copy is authoritative; nothing the relay sends can widen or revive it.
type liveGrant struct {
	req      proto.ConsentRequest
	cap      proto.Capability
	state    string // proto.Consent*
	lastUsed time.Time
	seq      uint64
	cancel   func(cause error) // ends the conversation; the adapter sees cause
}

type grantCache struct {
	mu     sync.Mutex
	grants map[string]liveGrant
}

func nonce() string {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// consentEnded is why the runner ended a consent conversation, as a
// proto.Reason* value. The adapter reads it as the cause of the request's
// context.
type consentEnded string

func (e consentEnded) Error() string { return string(e) }

// conversation is the context one consent conversation lives in. It ends at
// the requested grant's expiry, or when the runner ends it with a cause.
func conversation(parent context.Context, expires time.Time) (context.Context, func(error)) {
	ended, end := context.WithCancelCause(parent)
	ctx, stop := context.WithDeadlineCause(ended, expires, consentEnded(proto.ReasonExpired))
	return ctx, func(cause error) {
		end(cause)
		stop()
	}
}

// consent validates an access request, hands it to the local consent
// application, and acknowledges it immediately. The decision follows on
// proto.EvtConsent whenever the endpoint user makes one.
func (r *Runner) consent(ctx context.Context, cr proto.ConsentRequest) *proto.Response {
	if r.o.Consent == nil {
		return &proto.Response{Error: &proto.Error{Code: proto.ErrConsentRequired, Message: "no local consent application is available"}}
	}
	if cr.Device != r.deviceID || cr.Client != r.o.Enrollment.Client {
		return &proto.Response{Error: &proto.Error{Code: proto.ErrGrantInvalid, Message: "access request is bound to another endpoint"}}
	}
	now := time.Now().UTC()
	requestedExpiry := cr.ExpiresAt
	if requestedExpiry.IsZero() {
		requestedExpiry = now.Add(cr.Duration)
	}
	// The relay sets ExpiresAt by its own clock, so an hour-long grant it
	// forwards can end a little more than an hour from now by this machine's
	// clock. Allow the same skew as for approvals.
	if cr.AccessID == "" || cr.Technician == "" || cr.Purpose == "" || len(cr.Paths) == 0 || len(cr.Operations) == 0 || !requestedExpiry.After(now) || requestedExpiry.After(now.Add(proto.MaxConsentDuration+proto.ApprovalClockSkew)) || cr.Duration <= 0 || cr.Duration > proto.MaxConsentDuration || cr.IdleTimeout < 0 || cr.IdleTimeout > cr.Duration {
		return &proto.Response{Error: &proto.Error{Code: proto.ErrBadRequest, Message: "invalid consent identity, scope, or lifetime"}}
	}
	// The whole conversation lives inside the requested grant lifetime, so a
	// consent window can never outlive the authority it would create.
	cctx, cancel := conversation(ctx, requestedExpiry)
	r.grants.mu.Lock()
	if _, dup := r.grants.grants[cr.AccessID]; dup {
		r.grants.mu.Unlock()
		cancel(nil)
		return &proto.Response{Error: &proto.Error{Code: proto.ErrGrantInvalid, Message: "this access request has already been presented to the endpoint user"}}
	}
	r.grants.grants[cr.AccessID] = liveGrant{req: cr, state: proto.ConsentAwaiting, lastUsed: now, cancel: cancel}
	r.grants.mu.Unlock()
	r.saveGrants()

	updates, err := r.o.Consent.Request(cctx, cr)
	if err != nil || updates == nil {
		r.dropGrant(cr.AccessID, nil)
		cancel(nil)
		r.log.Warn("local consent application refused the request", "access", cr.AccessID, "err", err)
		msg := "the local consent application could not show the request"
		if cr.Approval != nil && err != nil {
			// A request under a technician unlock is decided by the endpoint
			// itself, so say why it was not approved. The adapters' reasons
			// name no secret; they never include the assertion.
			msg = "the endpoint did not approve this request: " + err.Error()
		}
		return &proto.Response{Error: &proto.Error{Code: proto.ErrConsentRequired, Message: msg}}
	}
	go r.consentUpdates(cctx, cr, requestedExpiry, updates)

	b, _ := json.Marshal(proto.ConsentDecision{State: proto.ConsentAwaiting})
	return &proto.Response{OK: true, Result: b}
}

// consentUpdates turns one adapter conversation into endpoint state and
// relay events. It denies the request itself if nobody decides within
// proto.ConsentTimeout, so an unattended machine fails closed without the
// relay having to ask.
func (r *Runner) consentUpdates(ctx context.Context, cr proto.ConsentRequest, expires time.Time, updates <-chan proto.ConsentUpdate) {
	decided, supervised, waiting := false, true, ""
	window := r.o.ConsentWindow
	if window <= 0 {
		window = proto.ConsentTimeout
	}
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	for {
		select {
		case u, ok := <-updates:
			if !ok {
				// The application stopped talking. An undecided request is
				// refused; a live grant pauses until the application is back,
				// so a crashed or closed window fails closed instead of
				// letting the session continue unwatched.
				if !decided {
					r.applyConsent(cr, proto.ConsentUpdate{State: proto.ConsentDenied, Reason: firstNonEmpty(waiting, proto.ReasonNoUser)}, expires)
					return
				}
				if !supervised {
					return // the adapter said it had nothing more to report
				}
				if r.applyConsent(cr, proto.ConsentUpdate{State: proto.ConsentPaused, Reason: proto.ReasonUIGone}, expires) {
					return
				}
				if updates = r.reopen(ctx, cr); updates == nil {
					return
				}
				continue
			}
			if u.State == proto.ConsentAwaiting {
				waiting = u.Reason
				r.publishConsent(cr, u, nil)
				continue
			}
			decided, supervised = true, supervised && !u.Final
			if terminal := r.applyConsent(cr, u, expires); terminal {
				return
			}
		case <-deadline.C:
			if !decided {
				r.applyConsent(cr, proto.ConsentUpdate{State: proto.ConsentDenied, Reason: firstNonEmpty(waiting, proto.ReasonTimeout)}, expires)
				return
			}
		case <-ctx.Done():
			// Expiry and endpoint shutdown both end the conversation. The
			// relay enforces the same expiry, so no event is needed.
			return
		}
	}
}

// reopenDelay is how long the endpoint waits before asking the consent
// application to show a paused grant again, doubling up to reopenMaxDelay so
// an application that keeps dying does not spin the service.
const (
	reopenDelay    = 250 * time.Millisecond
	reopenMaxDelay = 30 * time.Second
)

// reopen waits for the consent application to come back and present a live
// grant again. The grant stays paused until it does.
func (r *Runner) reopen(ctx context.Context, cr proto.ConsentRequest) <-chan proto.ConsentUpdate {
	for delay := reopenDelay; ; delay = min(delay*2, reopenMaxDelay) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if r.o.Consent == nil {
			return nil
		}
		ch, err := r.o.Consent.Request(ctx, cr)
		if err == nil && ch != nil {
			r.log.Info("consent application is showing a paused grant again", "access", cr.AccessID)
			return ch
		}
		r.log.Warn("consent application is still unavailable", "access", cr.AccessID, "err", err)
	}
}

// applyConsent records one decision or transition in the live grant cache
// and publishes it. It reports whether the grant is finished.
func (r *Runner) applyConsent(cr proto.ConsentRequest, u proto.ConsentUpdate, expires time.Time) bool {
	now := time.Now().UTC()
	r.grants.mu.Lock()
	g, ok := r.grants.grants[cr.AccessID]
	if !ok {
		r.grants.mu.Unlock()
		return true // already ended, by the technician or by shutdown
	}
	var cap *proto.Capability
	terminal := false
	switch u.State {
	case proto.ConsentApproved, proto.ConsentNarrowed:
		if g.state == proto.ConsentPaused && g.cap.GrantID != "" {
			g.state, g.lastUsed = proto.ConsentApproved, now // resume keeps the same capability
			cap = &g.cap
			break
		}
		if g.cap.GrantID != "" {
			// A decision is made once. A repeated approval, or a resume of a
			// grant that is not paused, must not mint a capability the relay
			// would never accept; the grant keeps the one it has.
			r.grants.mu.Unlock()
			r.log.Warn("ignored an approval of a grant that is already live", "access", cr.AccessID, "state", g.state)
			return false
		}
		if err := checkConsentScope(r.o.Host.OS, cr, u); err != nil {
			r.grants.mu.Unlock()
			r.log.Error("local consent tried to widen the request", "access", cr.AccessID, "err", err)
			r.dropGrant(cr.AccessID, consentEnded(err.Error()))
			r.publishConsent(cr, proto.ConsentUpdate{State: proto.ConsentDenied, Reason: err.Error()}, nil)
			return true
		}
		c := proto.Capability{GrantID: nonce(), AccessID: cr.AccessID, Nonce: nonce(), Client: cr.Client, Device: cr.Device,
			Technician: cr.Technician, Operations: slices.Clone(u.Operations), Paths: slices.Clone(u.Paths),
			IssuedAt: now, ExpiresAt: expires, IdleTimeout: cr.IdleTimeout, PolicyVersion: cr.PolicyVersion,
			EndpointConsent: cr.EndpointConsent}
		// The grant remembers the unlock behind it: authorize narrows such a
		// grant to the client's policy, and fstools asks each change under it
		// for the technician's own approval.
		if cr.Approval != nil {
			c.Unlock = cr.Approval.ID
		}
		g.cap, g.state, g.lastUsed = c, u.State, now
		cap = &c
	case proto.ConsentPaused:
		if g.cap.GrantID == "" || g.state == proto.ConsentPaused {
			// Only a grant can be paused, and pausing it twice changes nothing.
			r.grants.mu.Unlock()
			return false
		}
		g.state = proto.ConsentPaused
	case proto.ConsentDenied, proto.ConsentTerminated:
		terminal = true
	default:
		r.grants.mu.Unlock()
		r.log.Warn("local consent reported an unknown state", "access", cr.AccessID, "state", u.State)
		return false
	}
	g.seq++
	seq := g.seq
	if terminal {
		if g.cancel != nil {
			defer g.cancel(consentEnded(firstNonEmpty(u.Reason, u.State)))
		}
		delete(r.grants.grants, cr.AccessID)
	} else {
		r.grants.grants[cr.AccessID] = g
	}
	r.grants.mu.Unlock()
	r.saveGrants()
	r.publishConsentSeq(cr, u, cap, seq)
	return terminal
}

// checkConsentScope keeps the endpoint's own promise: local consent may only
// narrow what the technician asked for.
func checkConsentScope(goos string, cr proto.ConsentRequest, u proto.ConsentUpdate) error {
	if u.Approver == "" || len(u.Paths) == 0 || len(u.Operations) == 0 {
		return errConsent("approval has no approver or effective scope")
	}
	requested := make([]proto.AllowRule, len(cr.Paths))
	for i, p := range cr.Paths {
		requested[i] = proto.AllowRule{Path: p}
	}
	for _, op := range u.Operations {
		if !slices.Contains(cr.Operations, op) {
			return errConsent("local consent widened the requested operations")
		}
	}
	for _, p := range u.Paths {
		if _, _, ok := policy.MatchAllow(goos, requested, p, true); !ok {
			return errConsent("local consent widened the requested path scope")
		}
	}
	return nil
}

type errConsent string

func (e errConsent) Error() string { return string(e) }

func (r *Runner) publishConsent(cr proto.ConsentRequest, u proto.ConsentUpdate, cap *proto.Capability) {
	r.publishConsentSeq(cr, u, cap, 0)
}

func (r *Runner) publishConsentSeq(cr proto.ConsentRequest, u proto.ConsentUpdate, cap *proto.Capability, seq uint64) {
	ev := proto.ConsentEvent{AccessID: cr.AccessID, Client: cr.Client, Device: cr.Device, Technician: cr.Technician,
		State: u.State, Approver: u.Approver, ApproverSession: u.ApproverSession, Reason: u.Reason,
		Operations: u.Operations, Paths: u.Paths, Capability: cap, Seq: seq, Time: time.Now().UTC()}
	r.publishEvent(proto.EvtConsent, ev)
	r.log.Info("consent transition", "access", cr.AccessID, "state", u.State, "reason", u.Reason, "approver", u.Approver)
}

func (r *Runner) dropGrant(accessID string, cause error) {
	r.grants.mu.Lock()
	if g, ok := r.grants.grants[accessID]; ok {
		delete(r.grants.grants, accessID)
		if g.cancel != nil {
			defer g.cancel(cause)
		}
	}
	r.grants.mu.Unlock()
	r.saveGrants()
}

func (r *Runner) endAccess(a proto.EndAccessArgs) *proto.Response {
	r.grants.mu.Lock()
	g, ok := r.grants.grants[a.AccessID]
	if !ok {
		r.grants.mu.Unlock()
		return &proto.Response{Error: &proto.Error{Code: proto.ErrGrantInvalid, Message: "access grant is unknown or already ended"}}
	}
	// Reducing access is always possible, so the access ID is enough. The
	// relay may quote no capability, or an older view of it: it records a
	// termination before an approval that crossed it in flight reaches it,
	// and the endpoint must still let go of the grant.
	if a.GrantID != g.cap.GrantID || a.Nonce != g.cap.Nonce {
		r.log.Info("ending a grant the relay knew only by its access ID", "access", a.AccessID, "state", g.state)
	}
	delete(r.grants.grants, a.AccessID)
	r.grants.mu.Unlock()
	if g.cancel != nil {
		g.cancel(consentEnded(proto.ReasonTechnician)) // closes the request in the consent application
	}
	r.saveGrants()
	b, _ := json.Marshal(map[string]string{"state": proto.ConsentTerminated})
	return &proto.Response{OK: true, Result: b}
}

func (r *Runner) authorize(req *proto.Request) *proto.Error {
	c := req.Capability
	if c == nil {
		return nil
	} // migration compatibility for client-bound sessions
	r.grants.mu.Lock()
	defer r.grants.mu.Unlock()
	g, ok := r.grants.grants[c.AccessID]
	now := time.Now().UTC()
	if ok && g.state == proto.ConsentPaused {
		return &proto.Error{Code: proto.ErrGrantInvalid, Message: "the endpoint user has paused this access"}
	}
	// Unlock and EndpointConsent decide how the grant's paths are applied
	// below and whether a change needs the technician's approval, so a
	// capability that drops or flips either is not the grant.
	if !ok || (g.state != proto.ConsentApproved && g.state != proto.ConsentNarrowed) || g.cap.GrantID != c.GrantID || g.cap.Nonce != c.Nonce || g.cap.Client != c.Client || g.cap.Device != c.Device || g.cap.Technician != c.Technician || !slices.Equal(g.cap.Operations, c.Operations) || !slices.Equal(g.cap.Paths, c.Paths) || !g.cap.IssuedAt.Equal(c.IssuedAt) || !g.cap.ExpiresAt.Equal(c.ExpiresAt) || g.cap.IdleTimeout != c.IdleTimeout || g.cap.PolicyVersion != c.PolicyVersion || g.cap.Unlock != c.Unlock || g.cap.EndpointConsent != c.EndpointConsent || c.PolicyVersion != req.Policy.Version || c.Client != r.o.Enrollment.Client || c.Device != r.deviceID || c.Technician != req.Caller.Tech || !slices.Contains(c.Operations, req.Op) || !now.Before(c.ExpiresAt) || (c.IdleTimeout > 0 && now.Sub(g.lastUsed) >= c.IdleTimeout) {
		return &proto.Error{Code: proto.ErrGrantInvalid, Message: "access grant is expired, revoked, replayed, or does not match this operation"}
	}
	g.lastUsed = now
	r.grants.grants[c.AccessID] = g
	req.Policy.Allow = grantRules(r.o.Host.OS, req.Policy.Allow, g.cap)
	return nil
}

// grantRules is the allow list an operation under grant runs with. A person
// at the machine approved the paths of a legacy grant, and of one the client's
// policy also put to them, so those paths replace the policy's rules, as in
// Slice 3. Nobody at the machine saw the paths of a grant approved on a
// technician unlock alone, so they only narrow the client's policy: approving
// a request without a person must never let it reach what the policy does
// not allow.
func grantRules(goos string, policyRules []proto.AllowRule, grant proto.Capability) []proto.AllowRule {
	if grant.Unlock != "" && !grant.EndpointConsent {
		return policy.Narrow(goos, policyRules, grant.Paths)
	}
	rules := make([]proto.AllowRule, len(grant.Paths))
	for i, p := range grant.Paths {
		rules[i] = proto.AllowRule{ID: "grant-" + grant.AccessID, Path: p}
	}
	return rules
}

// activity shows one operation performed under a grant in the local consent
// application, which is what makes an active session visible to the person
// who approved it.
func (r *Runner) activity(req *proto.Request, resp *proto.Response) {
	if r.o.Consent == nil || req.Capability == nil {
		return
	}
	var args struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(req.Args, &args)
	a := proto.ConsentActivity{AccessID: req.Capability.AccessID, Op: req.Op, Path: args.Path,
		Bytes: resp.Meta.Bytes, Time: time.Now().UTC()}
	if resp.Error != nil {
		a.ErrorCode = resp.Error.Code
	}
	r.o.Consent.Activity(a)
}

// grantRecord is one line of the live-grant file. It holds no capability
// material: its only purpose is to let a restarted service tell the relay
// that the grants it was holding are gone.
type grantRecord struct {
	AccessID   string `json:"access_id"`
	Client     string `json:"client"`
	Device     string `json:"device"`
	Technician string `json:"technician"`
}

// saveGrants records the access IDs this service is holding. A service
// restart drops every live grant, and the file is what lets the restarted
// service say so instead of leaving the relay with a grant nobody honours.
func (r *Runner) saveGrants() {
	if r.o.GrantsFile == "" {
		return
	}
	r.grants.mu.Lock()
	recs := make([]grantRecord, 0, len(r.grants.grants))
	for id, g := range r.grants.grants {
		recs = append(recs, grantRecord{AccessID: id, Client: g.req.Client, Device: g.req.Device, Technician: g.req.Technician})
	}
	r.grants.mu.Unlock()
	slices.SortFunc(recs, func(a, b grantRecord) int { return strings.Compare(a.AccessID, b.AccessID) })
	b, err := json.Marshal(recs)
	if err == nil {
		err = writeFilePrivate(r.o.GrantsFile, b)
	}
	if err != nil {
		r.log.Warn("could not record live grants", "path", r.o.GrantsFile, "err", err)
	}
}

// terminateStaleGrants publishes a termination for every grant the previous
// run of this service was holding. Restarting clears the live grant cache,
// so those grants are already unusable; this makes the relay agree.
func (r *Runner) terminateStaleGrants() {
	if r.o.GrantsFile == "" {
		return
	}
	b, err := os.ReadFile(r.o.GrantsFile)
	if err != nil {
		return
	}
	var recs []grantRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		r.log.Warn("unreadable live-grant file", "path", r.o.GrantsFile, "err", err)
	}
	for _, rec := range recs {
		if rec.AccessID == "" || rec.Device != r.deviceID {
			continue
		}
		r.publishConsent(proto.ConsentRequest{AccessID: rec.AccessID, Client: rec.Client, Device: rec.Device, Technician: rec.Technician},
			proto.ConsentUpdate{State: proto.ConsentTerminated, Reason: proto.ReasonRestart}, nil)
	}
	if err := os.Remove(r.o.GrantsFile); err != nil && !os.IsNotExist(err) {
		r.log.Warn("could not clear the live-grant file", "path", r.o.GrantsFile, "err", err)
	}
}

func writeFilePrivate(path string, b []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, b, 0o600)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
