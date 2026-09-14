package consentipc

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// DefaultSessionPoll is how often the hub checks that whoever approved a
// live grant is still signed in.
const DefaultSessionPoll = 2 * time.Second

// Hub is the service's side of local consent: it holds the requests the
// endpoint user has been asked about, shows them in every interactive
// session, and turns the answer into the updates the runner acts on. It
// implements agent.ConsentAdapter. The pipe transport is Windows-only;
// nothing here is, so the decision rules are tested on every platform.
//
// Two rules matter more than the rest. Only an elevated peer may approve or
// narrow, because approval is an elevation gate; and anyone who can reach
// the pipe may deny, pause or terminate, because reducing access must always
// be possible.
//
// The hub also keeps every window truthful. A grant nobody can watch is
// paused, a grant whose approver signed out is ended, and when the runner is
// finished with a request — the technician ended it, it expired, the consent
// window closed on it — every window is told why and the request is gone.
type Hub struct {
	log      *slog.Logger
	launch   func(session string) error // start the consent application in a session
	sessions func() []string            // interactive sessions right now
	now      func() time.Time
	poll     time.Duration

	mu    sync.Mutex
	views map[*View]struct{}
	reqs  map[string]*request
	plans map[string]*planReview // keyed by access ID: one pending review at a time
}

// HubOptions configures a Hub. The zero value of each is a safe default for
// tests: no launching, no sessions, real time.
type HubOptions struct {
	Logger   *slog.Logger
	Launch   func(session string) error
	Sessions func() []string
	Now      func() time.Time
	// SessionPoll is how often a live grant's approver is checked for having
	// signed out. 0 means DefaultSessionPoll.
	SessionPoll time.Duration
}

// View is one connected, already verified consent application: one window in
// one OS session. The transport fills it in from the pipe, never from
// anything the application claims.
type View struct {
	Session  string // OS session ID
	User     string // the signed-in user, for the audit record of who approved
	Elevated bool   // the peer holds an elevated token
	Send     func(Envelope)
}

type request struct {
	view      RequestView
	updates   chan proto.ConsentUpdate
	ctx       context.Context // the runner's: done when it is finished with the request
	decided   bool
	live      bool   // approved and not yet finished
	held      bool   // paused by the endpoint user, not merely for want of a window
	granted   string // approved or narrowed
	approver  string
	session   string // the OS session the approval came from
	effective []string
	closed    bool          // the runner has been told the conversation is over
	finished  bool          // every window has been told the request ended
	waiting   string        // why it is still undecided
	closeCh   chan struct{} // closed once, exactly when closed becomes true
}

// planReview is one pending review of a staged change: at most one per
// access ID. It ends exactly once, however that happens — a decision, ctx
// expiring, its request's conversation closing, or a newer review replacing
// it — and the answer channel is never sent on or closed twice.
type planReview struct {
	accessID string
	digest   string
	view     PlanView // what was shown, so a window that connects late sees the same thing
	answer   chan proto.ConsentDecision
	doneCh   chan struct{} // closed once the review has ended, so its watcher goroutine can exit
	closed   bool          // guarded by h.mu
}

// NewHub returns a Hub with no consent applications connected yet.
func NewHub(o HubOptions) *Hub {
	h := &Hub{
		log:      cmp.Or(o.Logger, slog.New(slog.DiscardHandler)),
		launch:   o.Launch,
		sessions: o.Sessions,
		now:      o.Now,
		poll:     cmp.Or(o.SessionPoll, DefaultSessionPoll),
		views:    map[*View]struct{}{},
		reqs:     map[string]*request{},
		plans:    map[string]*planReview{},
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h
}

// ReviewChange is the asynchronous review fstools asks for: it validates the
// plan and shows it to every connected window, then returns at once. The
// caller reads at most one decision from the returned channel, which is then
// closed; ctx bounds how long the review stays pending. It never blocks on
// the endpoint user.
func (h *Hub) ReviewChange(ctx context.Context, cr proto.ConsentRequest) (<-chan proto.ConsentDecision, error) {
	var plan proto.ChangePlan
	if err := json.Unmarshal(cr.Plan, &plan); err != nil || cr.AccessID == "" || cr.PlanDigest == "" || plan.PlanDigest != cr.PlanDigest {
		return nil, errors.New("invalid change review")
	}
	h.mu.Lock()
	r := h.reqs[cr.AccessID]
	if r == nil || !r.live || r.closed || len(h.views) == 0 {
		h.mu.Unlock()
		return nil, errors.New("no local consent window is watching this grant")
	}
	prev := h.plans[cr.AccessID]
	pr := &planReview{
		accessID: cr.AccessID,
		digest:   cr.PlanDigest,
		view: PlanView{AccessID: cr.AccessID, Digest: cr.PlanDigest, Path: plan.Before.Path, Diff: plan.Diff,
			Reason: cmp.Or(plan.Reason, cr.Purpose), Technician: cr.Technician, ExpiresAt: plan.ExpiresAt},
		answer: make(chan proto.ConsentDecision, 1),
		doneCh: make(chan struct{}),
	}
	h.plans[cr.AccessID] = pr
	views := h.viewList()
	h.mu.Unlock()

	if prev != nil {
		// A new review for this access ID replaces whatever was pending: the
		// old one ends before the new one is shown.
		h.endReview(prev, "replaced by a newer change")
	}
	view := pr.view
	for _, v := range views {
		v.Send(Envelope{Type: TypePlan, Plan: &view})
	}
	go h.watchReview(ctx, r, pr)
	return pr.answer, nil
}

// watchReview ends pr the moment nothing can answer it any more: ctx expires,
// or the request it belongs to stops being usable — the runner is finished
// with it, or its conversation with the endpoint closed (a window loss that
// pauses the grant included). It also exits as soon as pr ends some other
// way (a decision, or a newer review replacing it), so it never leaks.
func (h *Hub) watchReview(ctx context.Context, r *request, pr *planReview) {
	select {
	case <-ctx.Done():
		h.endReview(pr, "the change plan expired")
	case <-r.closeCh:
		h.endReview(pr, "the access grant ended or its consent window closed")
	case <-pr.doneCh:
	}
}

// claimReview marks pr ended if nothing already has, so exactly one caller
// ever performs the actual ending. It also drops pr from h.plans, but only
// while pr is still the entry there: a review a newer one already replaced
// removed itself from the map when it was replaced.
func (h *Hub) claimReview(pr *planReview) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if pr.closed {
		return false
	}
	pr.closed = true
	if h.plans[pr.accessID] == pr {
		delete(h.plans, pr.accessID)
	}
	return true
}

// endReview ends pr with no decision: ctx expired, its request's
// conversation closed, or a newer review replaced it.
func (h *Hub) endReview(pr *planReview, reason string) {
	if !h.claimReview(pr) {
		return
	}
	close(pr.answer)
	close(pr.doneCh)
	h.broadcast(Envelope{Type: TypePlanState, PlanState: &PlanStateView{
		AccessID: pr.accessID, Digest: pr.digest, State: PlanEnded, Reason: reason}})
}

// DecidePlan records the endpoint user's review of a staged change. Only
// approve and deny are answers; approving requires an elevated window,
// because approval is the elevation gate, but denying — like every other way
// of reducing access — is accepted from any verified one. A digest that is
// not exactly what is pending (never reviewed, already answered, ended, or
// replaced by a newer plan) is refused, so a late click never lands on the
// wrong review.
func (h *Hub) DecidePlan(v *View, d PlanDecision) error {
	if d.Decision != DecideApprove && d.Decision != DecideDeny {
		return errors.New("invalid plan decision")
	}
	h.mu.Lock()
	pr := h.plans[d.AccessID]
	if pr == nil || pr.closed || pr.digest != d.Digest {
		h.mu.Unlock()
		return errors.New("no matching change review")
	}
	if d.Decision == DecideApprove && !v.Elevated {
		h.mu.Unlock()
		return errors.New("approving a change requires elevation")
	}
	pr.closed = true
	delete(h.plans, d.AccessID)
	h.mu.Unlock()

	state, planState := proto.ConsentDenied, PlanDenied
	if d.Decision == DecideApprove {
		state, planState = proto.ConsentApproved, PlanApproved
	}
	pr.answer <- proto.ConsentDecision{State: state, Approver: v.User, PlanDigest: d.Digest}
	close(pr.answer)
	close(pr.doneCh)
	h.broadcast(Envelope{Type: TypePlanState, PlanState: &PlanStateView{
		AccessID: d.AccessID, Digest: d.Digest, State: planState, Approver: v.User}})
	return nil
}

// Request shows an access request in every interactive session and returns
// the channel the runner listens on. It never waits for the user. The
// request lives as long as ctx: once the runner is done with it, for any
// reason, every window is told and the hub forgets it.
func (h *Hub) Request(ctx context.Context, cr proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	h.mu.Lock()
	prev := h.reqs[cr.AccessID]
	r := &request{
		view: RequestView{AccessID: cr.AccessID, Client: cr.Client, Device: cr.Device, Technician: cr.Technician,
			Purpose: cr.Purpose, Paths: slices.Clone(cr.Paths), Operations: slices.Clone(cr.Operations),
			Duration: cr.Duration, IdleTimeout: cr.IdleTimeout, ExpiresAt: cr.ExpiresAt,
			DecideBy: h.now().Add(proto.ConsentTimeout).UTC(), State: proto.ConsentAwaiting},
		updates: make(chan proto.ConsentUpdate, 8),
		ctx:     ctx,
		closeCh: make(chan struct{}),
	}
	// A request the service is showing again after the consent application
	// went away keeps what the user already granted, and any pause they chose.
	if prev != nil && prev.live {
		r.decided, r.live, r.held, r.granted = true, true, prev.held, prev.granted
		r.approver, r.session, r.effective = prev.approver, prev.session, slices.Clone(prev.effective)
		// It stays paused on screen until a window is back to watch it.
		r.view.State, r.view.Approver, r.view.Effective = proto.ConsentPaused, prev.approver, slices.Clone(prev.effective)
	}
	h.reqs[cr.AccessID] = r
	view, views := r.view, h.viewList()
	h.mu.Unlock()
	go h.watch(r)

	if r.live {
		// The approver signed out while no window of theirs was open to see
		// it: the grant ends now, as it would have then.
		if !h.signedIn(r.session) {
			h.end(r, proto.ConsentTerminated, proto.ReasonLogoff)
			return r.updates, nil
		}
		go h.watchSession(r)
	}
	for _, v := range views {
		v.Send(Envelope{Type: TypeRequest, Request: &view})
	}
	switch {
	case len(views) == 0:
		h.present(r)
	case r.live && !r.held:
		// A window is already watching, so the pause that brought this grant
		// back to the screen is over.
		h.resume(r, proto.ReasonUIRestored)
	}
	return r.updates, nil
}

// present asks the transport to start a consent application wherever a
// person could answer, and says so when nobody can.
func (h *Hub) present(r *request) {
	var sessions []string
	if h.sessions != nil {
		sessions = h.sessions()
	}
	if len(sessions) == 0 {
		h.mu.Lock()
		undecided := !r.decided
		if undecided {
			r.waiting = proto.ReasonNoUser
		}
		h.mu.Unlock()
		// Nobody is signed in. An undecided request stays open until the
		// endpoint's consent window closes, which is when it is refused; if
		// someone signs in before then, they are asked. A grant that is only
		// waiting for its window to reappear stays paused instead.
		if undecided {
			h.send(r, proto.ConsentUpdate{State: proto.ConsentAwaiting, Reason: proto.ReasonNoUser})
		}
		return
	}
	// A locked session still has its user and is still asked: the request
	// waits behind the lock screen until it is answered or refused.
	for _, s := range sessions {
		if h.launch == nil {
			continue
		}
		if err := h.launch(s); err != nil {
			h.log.Warn("could not start the consent application", "session", s, "err", err)
		}
	}
}

// signedIn reports whether session still has a signed-in user. A hub that
// cannot list sessions assumes it has, so that it never ends a grant on a
// guess; the grant is still paused while no window watches it.
func (h *Hub) signedIn(session string) bool {
	return h.sessions == nil || session == "" || slices.Contains(h.sessions(), session)
}

// watch closes a request on screen once the runner is finished with it, so
// that no window goes on offering a decision, or a Pause button, for
// authority that no longer exists. The runner says why as ctx's cause.
func (h *Hub) watch(r *request) {
	<-r.ctx.Done()
	h.mu.Lock()
	id := r.view.AccessID
	current := h.reqs[id] == r
	if current {
		delete(h.reqs, id)
	}
	told, decided := r.finished, r.decided
	r.live = false
	h.mu.Unlock()
	if current && !told {
		state := proto.ConsentTerminated
		if !decided {
			state = proto.ConsentDenied
		}
		h.broadcast(Envelope{Type: TypeState, State: &StateView{AccessID: id, State: state, Reason: endReason(r.ctx)}})
	}
	h.close(r)
}

// endReason is why the runner ended a request, when it said.
func endReason(ctx context.Context) string {
	cause := context.Cause(ctx)
	if cause == nil || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return ""
	}
	return cause.Error()
}

// watchSession ends a live grant whose approver has signed out. A window in
// that session reports the sign-out itself when its pipe closes; this
// catches the sign-outs no window was there to see, because the approver's
// window had already crashed or been closed.
func (h *Hub) watchSession(r *request) {
	if h.sessions == nil || r.session == "" {
		return
	}
	t := time.NewTicker(h.poll)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		gone := h.reqs[r.view.AccessID] != r || r.closed || !r.live
		h.mu.Unlock()
		if gone {
			return
		}
		if !h.signedIn(r.session) {
			h.end(r, proto.ConsentTerminated, proto.ReasonLogoff)
			return
		}
	}
}

// Activity shows one operation in every connected window.
func (h *Hub) Activity(a proto.ConsentActivity) {
	h.mu.Lock()
	views := h.viewList()
	_, known := h.reqs[a.AccessID]
	h.mu.Unlock()
	if !known {
		return
	}
	act := a
	for _, v := range views {
		v.Send(Envelope{Type: TypeActivity, Activity: &act})
	}
}

// AddView registers a verified consent application and catches it up on
// every request the endpoint is holding.
func (h *Hub) AddView(v *View) {
	h.mu.Lock()
	h.views[v] = struct{}{}
	reqs := make([]RequestView, 0, len(h.reqs))
	var shown, resumed []*request
	for _, r := range h.reqs {
		if r.closed {
			continue
		}
		reqs = append(reqs, r.view)
		switch {
		case !r.decided && r.waiting != "":
			r.waiting = ""
			shown = append(shown, r)
		case r.live && !r.held && r.view.State == proto.ConsentPaused:
			resumed = append(resumed, r)
		}
	}
	plans := make([]PlanView, 0, len(h.plans))
	for _, pr := range h.plans {
		plans = append(plans, pr.view)
	}
	h.mu.Unlock()
	slices.SortFunc(reqs, func(a, b RequestView) int { return a.DecideBy.Compare(b.DecideBy) })
	for _, rv := range reqs {
		view := rv
		v.Send(Envelope{Type: TypeRequest, Request: &view})
	}
	// A request that was waiting for somebody to sign in is now on screen.
	for _, r := range shown {
		h.send(r, proto.ConsentUpdate{State: proto.ConsentAwaiting})
	}
	// A grant paused only because no window was watching it resumes now that
	// one is. A grant the endpoint user paused stays paused until they resume it.
	for _, r := range resumed {
		h.resume(r, proto.ReasonUIRestored)
	}
	// A change review still pending is shown last, after the requests it
	// belongs to.
	for _, pv := range plans {
		view := pv
		v.Send(Envelope{Type: TypePlan, Plan: &view})
	}
	h.log.Info("consent application connected", "session", v.Session, "user", v.User, "elevated", v.Elevated)
}

// RemoveView drops a disconnected consent application. When the last one
// goes, every live grant stops: a grant nobody can watch is paused, and one
// whose approver signed out is ended.
func (h *Hub) RemoveView(v *View, sessionEnded bool) {
	h.mu.Lock()
	delete(h.views, v)
	remaining := len(h.views)
	var ended, orphaned, unattended []*request
	for _, r := range h.reqs {
		switch {
		case r.closed:
		case r.live && sessionEnded && r.session == v.Session:
			ended = append(ended, r)
		case r.live && remaining == 0:
			orphaned = append(orphaned, r)
		case !r.decided && remaining == 0 && sessionEnded:
			unattended = append(unattended, r)
		}
	}
	h.mu.Unlock()
	h.log.Info("consent application disconnected", "session", v.Session, "user", v.User,
		"session_ended", sessionEnded, "remaining", remaining)
	for _, r := range ended {
		h.end(r, proto.ConsentTerminated, proto.ReasonLogoff)
	}
	for _, r := range orphaned {
		// Closing the conversation is what tells the runner the window is
		// gone: it pauses the grant and asks for it to be shown again.
		h.close(r)
	}
	// The last user signed out with a request still undecided. Say why nobody
	// is answering, so the refusal at the deadline says no_user.
	if len(unattended) > 0 && (h.sessions == nil || len(h.sessions()) == 0) {
		for _, r := range unattended {
			h.mu.Lock()
			r.waiting = proto.ReasonNoUser
			h.mu.Unlock()
			h.send(r, proto.ConsentUpdate{State: proto.ConsentAwaiting, Reason: proto.ReasonNoUser})
		}
	}
}

// Decide records the endpoint user's answer. The first answer wins, however
// many sessions were shown the request.
func (h *Hub) Decide(v *View, d Decision) error {
	if d.Decision != DecideApprove && d.Decision != DecideDeny {
		return errors.New("consentipc: unknown decision")
	}
	h.mu.Lock()
	r, ok := h.reqs[d.AccessID]
	if !ok || r.closed || r.ctx.Err() != nil {
		h.mu.Unlock()
		return errors.New("consentipc: no such access request")
	}
	if r.decided {
		h.mu.Unlock()
		h.log.Info("a later answer was ignored", "access", d.AccessID, "session", v.Session)
		return nil
	}
	if d.Decision == DecideApprove && !v.Elevated {
		h.mu.Unlock()
		return errors.New("consentipc: approving requires an elevated consent application")
	}
	paths, err := selected(r.view.Paths, d.Select)
	if err != nil && d.Decision == DecideApprove {
		h.mu.Unlock()
		return err
	}
	r.decided = true
	if d.Decision == DecideDeny {
		h.mu.Unlock()
		h.send(r, proto.ConsentUpdate{State: proto.ConsentDenied, Approver: v.User, ApproverSession: v.Session, Reason: d.Reason})
		h.finish(r, proto.ConsentDenied, d.Reason)
		return nil
	}
	state := proto.ConsentApproved
	if len(paths) != len(r.view.Paths) {
		state = proto.ConsentNarrowed
	}
	r.live, r.granted, r.approver, r.session, r.effective = true, state, v.User, v.Session, paths
	r.view.State, r.view.Approver, r.view.Effective = state, v.User, slices.Clone(paths)
	ops, expires := slices.Clone(r.view.Operations), r.view.ExpiresAt
	h.mu.Unlock()
	h.send(r, proto.ConsentUpdate{State: state, Approver: v.User, ApproverSession: v.Session,
		Paths: slices.Clone(paths), Operations: ops})
	h.broadcast(Envelope{Type: TypeState, State: &StateView{AccessID: d.AccessID, State: state,
		Approver: v.User, ExpiresAt: expires, Effective: slices.Clone(paths)}})
	go h.watchSession(r)
	return nil
}

// Control pauses, resumes or ends a live grant. None of these widen
// anything, so none of them need an elevated peer.
func (h *Hub) Control(v *View, c Control) error {
	h.mu.Lock()
	r, ok := h.reqs[c.AccessID]
	if !ok || r.closed || r.ctx.Err() != nil {
		h.mu.Unlock()
		return errors.New("consentipc: no such access request")
	}
	switch c.Action {
	case ControlEnd:
		h.mu.Unlock()
		h.end(r, proto.ConsentTerminated, proto.ReasonUser)
	case ControlPause:
		if !r.live {
			h.mu.Unlock()
			return errors.New("consentipc: only a granted access can be paused")
		}
		already := r.view.State == proto.ConsentPaused
		r.held = true
		h.mu.Unlock()
		if !already {
			h.setState(r, proto.ConsentPaused, proto.ReasonUser)
			h.send(r, proto.ConsentUpdate{State: proto.ConsentPaused, Reason: proto.ReasonUser})
		}
	case ControlResume:
		if !r.live || r.view.State != proto.ConsentPaused {
			h.mu.Unlock()
			return errors.New("consentipc: only a paused grant can be resumed")
		}
		r.held = false
		h.mu.Unlock()
		h.resume(r, proto.ReasonUser)
	default:
		h.mu.Unlock()
		return errors.New("consentipc: unknown control action")
	}
	h.log.Info("consent control", "access", c.AccessID, "action", c.Action, "session", v.Session)
	return nil
}

// Resume returns a grant that was paused for want of a window to use. It
// leaves alone a grant the endpoint user paused themselves.
func (h *Hub) Resume(accessID string) {
	h.mu.Lock()
	r, ok := h.reqs[accessID]
	held := ok && r.held
	h.mu.Unlock()
	if ok && !held {
		h.resume(r, proto.ReasonUIRestored)
	}
}

// resume returns a paused grant to use with the capability it already has.
func (h *Hub) resume(r *request, reason string) {
	h.mu.Lock()
	if r.closed || !r.live || r.view.State != proto.ConsentPaused {
		h.mu.Unlock()
		return
	}
	r.view.State = cmp.Or(r.granted, proto.ConsentApproved)
	approver, effective, ops := r.approver, slices.Clone(r.effective), slices.Clone(r.view.Operations)
	view := r.view
	h.mu.Unlock()
	h.broadcast(Envelope{Type: TypeState, State: &StateView{AccessID: view.AccessID, State: view.State, Reason: reason,
		Approver: view.Approver, ExpiresAt: view.ExpiresAt, Effective: view.Effective}})
	h.send(r, proto.ConsentUpdate{State: proto.ConsentApproved, Approver: approver, Reason: reason,
		Paths: effective, Operations: ops})
}

// Forget drops a request at once, without waiting for the runner.
func (h *Hub) Forget(accessID string) {
	h.mu.Lock()
	r := h.reqs[accessID]
	delete(h.reqs, accessID)
	h.mu.Unlock()
	if r != nil {
		h.close(r)
	}
}

// Requests returns what the endpoint is currently holding, for the window's
// initial state and for tests.
func (h *Hub) Requests() []RequestView {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]RequestView, 0, len(h.reqs))
	for _, r := range h.reqs {
		if !r.closed {
			out = append(out, r.view)
		}
	}
	slices.SortFunc(out, func(a, b RequestView) int { return a.DecideBy.Compare(b.DecideBy) })
	return out
}

func (h *Hub) setState(r *request, state, reason string) {
	h.mu.Lock()
	r.view.State = state
	view := r.view
	h.mu.Unlock()
	h.broadcast(Envelope{Type: TypeState, State: &StateView{AccessID: view.AccessID, State: state, Reason: reason,
		Approver: view.Approver, ExpiresAt: view.ExpiresAt, Effective: view.Effective}})
}

func (h *Hub) send(r *request, u proto.ConsentUpdate) {
	h.mu.Lock()
	closed := r.closed
	h.mu.Unlock()
	if closed {
		return
	}
	select {
	case r.updates <- u:
	case <-r.ctx.Done():
	}
}

// end finishes a request on the endpoint user's behalf: the runner is told,
// then every window.
func (h *Hub) end(r *request, state, reason string) {
	h.send(r, proto.ConsentUpdate{State: state, Reason: reason})
	h.finish(r, state, reason)
}

// finish ends a request for good and tells every window why.
func (h *Hub) finish(r *request, state, reason string) {
	h.mu.Lock()
	r.live, r.finished = false, true
	id := r.view.AccessID
	h.mu.Unlock()
	h.broadcast(Envelope{Type: TypeState, State: &StateView{AccessID: id, State: state, Reason: reason}})
	h.close(r)
}

func (h *Hub) close(r *request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.updates)
		close(r.closeCh)
	}
}

func (h *Hub) broadcast(e Envelope) {
	h.mu.Lock()
	views := h.viewList()
	h.mu.Unlock()
	for _, v := range views {
		v.Send(e)
	}
}

// viewList must be called with the lock held.
func (h *Hub) viewList() []*View {
	out := make([]*View, 0, len(h.views))
	for v := range h.views {
		out = append(out, v)
	}
	return out
}

// selected maps the indexes the user left ticked to paths. An empty
// selection means everything that was requested; an out-of-range index is a
// broken or hostile application and is refused rather than guessed at.
func selected(paths []string, idx []int) ([]string, error) {
	if len(idx) == 0 {
		return slices.Clone(paths), nil
	}
	seen := map[int]bool{}
	out := make([]string, 0, len(idx))
	for _, i := range idx {
		if i < 0 || i >= len(paths) || seen[i] {
			return nil, errors.New("consentipc: the consent application selected a path that was not offered")
		}
		seen[i] = true
		out = append(out, paths[i])
	}
	// Keep the order the request had, so the effective scope reads the same
	// way everywhere it is recorded.
	slices.SortFunc(out, func(a, b string) int {
		return cmp.Compare(slices.Index(paths, a), slices.Index(paths, b))
	})
	return out, nil
}
