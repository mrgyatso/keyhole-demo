package consentipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func testRequest() proto.ConsentRequest {
	return proto.ConsentRequest{AccessID: "acc_one", Client: "acme", Device: "dev_one", Technician: "alice",
		Purpose: "diagnose", Operations: []string{proto.OpReadFile},
		Paths:    []string{`C:\ProgramData\Vendor`, `C:\Windows\Logs`},
		Duration: 10 * time.Minute, ExpiresAt: time.Now().Add(10 * time.Minute)}
}

// view returns a connected consent application and the messages it is sent.
// The hub sends from its own goroutines too, so the record is locked.
func view(h *Hub, session, user string, elevated bool) (*View, func() []Envelope) {
	var mu sync.Mutex
	var sent []Envelope
	v := &View{Session: session, User: user, Elevated: elevated}
	v.Send = func(e Envelope) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, e)
	}
	return v, func() []Envelope {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sent)
	}
}

func next(t *testing.T, ch <-chan proto.ConsentUpdate) proto.ConsentUpdate {
	t.Helper()
	select {
	case u, ok := <-ch:
		if !ok {
			t.Fatal("the consent conversation closed unexpectedly")
		}
		return u
	case <-time.After(2 * time.Second):
		t.Fatal("no consent update")
	}
	return proto.ConsentUpdate{}
}

// closed waits for the runner's side of a conversation to end.
func closed(t *testing.T, ch <-chan proto.ConsentUpdate) {
	t.Helper()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the consent conversation stayed open")
		}
	}
}

func stateSent(sent func() []Envelope, accessID, state string) *StateView {
	for _, e := range sent() {
		if e.Type == TypeState && e.State.AccessID == accessID && e.State.State == state {
			return e.State
		}
	}
	return nil
}

// waitState waits for a window to be told a request moved to state. When
// the runner ends a request, the hub tells windows from its own goroutine.
func waitState(t *testing.T, sent func() []Envelope, accessID, state string) StateView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if sv := stateSent(sent, accessID, state); sv != nil {
			return *sv
		}
		if time.Now().After(deadline) {
			t.Fatalf("the window was never told %s is %s", accessID, state)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// signedIn is a mutable list of Windows sessions with a user.
type signedIn struct {
	mu   sync.Mutex
	list []string
}

func (s *signedIn) set(sessions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = slices.Clone(sessions)
}

func (s *signedIn) get() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.list)
}

func approve(t *testing.T, h *Hub, v *View, updates <-chan proto.ConsentUpdate) {
	t.Helper()
	if err := h.Decide(v, Decision{AccessID: "acc_one", Decision: DecideApprove}); err != nil {
		t.Fatal(err)
	}
	if u := next(t, updates); u.State != proto.ConsentApproved {
		t.Fatalf("approval: %+v", u)
	}
}

func TestHubApprovalRequiresElevationAndNarrows(t *testing.T) {
	h := NewHub(HubOptions{Sessions: func() []string { return []string{"2"} }})
	plain, _ := view(h, "2", "ACME\\sam", false)
	h.AddView(plain)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Decide(plain, Decision{AccessID: "acc_one", Decision: DecideApprove}); err == nil {
		t.Fatal("an unelevated consent application approved an access request")
	}
	// Reducing access never needs elevation.
	elevated, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(elevated)
	if err := h.Decide(elevated, Decision{AccessID: "acc_one", Decision: DecideApprove, Select: []int{1}}); err != nil {
		t.Fatal(err)
	}
	u := next(t, updates)
	if u.State != proto.ConsentNarrowed || len(u.Paths) != 1 || u.Paths[0] != `C:\Windows\Logs` {
		t.Fatalf("narrowed approval: %+v", u)
	}
	if u.Approver != "ACME\\sam" || u.ApproverSession != "2" {
		t.Fatalf("approver not recorded: %+v", u)
	}
	// A path that was never offered cannot be granted.
	h2 := NewHub(HubOptions{})
	other, _ := view(h2, "2", "ACME\\sam", true)
	h2.AddView(other)
	if _, err := h2.Request(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	if err := h2.Decide(other, Decision{AccessID: "acc_one", Decision: DecideApprove, Select: []int{5}}); err == nil {
		t.Fatal("the consent application selected a path that was not offered")
	}
	// Anything but approve or deny is a broken or hostile application.
	if err := h2.Decide(other, Decision{AccessID: "acc_one", Decision: "maybe"}); err == nil {
		t.Fatal("an unknown decision was accepted")
	}
}

func TestHubFirstSessionToAnswerWins(t *testing.T) {
	h := NewHub(HubOptions{})
	first, firstSent := view(h, "2", "ACME\\sam", true)
	second, secondSent := view(h, "3", "ACME\\kim", true)
	h.AddView(first)
	h.AddView(second)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	// Both windows are shown the request.
	for name, sent := range map[string]func() []Envelope{"first": firstSent, "second": secondSent} {
		if !slices.ContainsFunc(sent(), func(e Envelope) bool { return e.Type == TypeRequest }) {
			t.Fatalf("the %s session was not shown the request", name)
		}
	}
	if err := h.Decide(first, Decision{AccessID: "acc_one", Decision: DecideApprove}); err != nil {
		t.Fatal(err)
	}
	if err := h.Decide(second, Decision{AccessID: "acc_one", Decision: DecideDeny}); err != nil {
		t.Fatal(err)
	}
	u := next(t, updates)
	if u.State != proto.ConsentApproved || u.ApproverSession != "2" {
		t.Fatalf("the second session overrode the first: %+v", u)
	}
	// Decide sends synchronously, so a second decision would already be queued.
	if len(updates) != 0 {
		t.Fatalf("a second decision was reported: %+v", <-updates)
	}
	if stateSent(secondSent, "acc_one", proto.ConsentApproved) == nil {
		t.Fatal("the session that lost the race was not told the outcome")
	}
}

// changePlan is a plan small enough to review, with a Reason so tests can
// check it reaches the window.
func changePlan(digest string) proto.ChangePlan {
	return proto.ChangePlan{PlanDigest: digest, Before: proto.FileSnapshot{Path: `C:\Vendor\config.ini`},
		Diff: "-old\n+new\n", Reason: "fix the vendor config", ExpiresAt: time.Now().Add(time.Minute)}
}

// reviewRequest is the ConsentRequest ReviewChange takes: cr.Plan encodes a
// changePlan(digest), and cr.PlanDigest matches it.
func reviewRequest(t *testing.T, accessID, digest string) proto.ConsentRequest {
	t.Helper()
	raw, err := json.Marshal(changePlan(digest))
	if err != nil {
		t.Fatal(err)
	}
	return proto.ConsentRequest{AccessID: accessID, PlanDigest: digest, Plan: raw, Technician: "alice", Purpose: "diagnose"}
}

// liveGrant returns a hub with access request "acc_one" approved by an
// elevated view watching it, ready for a change review.
func liveGrant(t *testing.T, ctx context.Context) (*Hub, *View, func() []Envelope, <-chan proto.ConsentUpdate) {
	t.Helper()
	h := NewHub(HubOptions{})
	v, sent := view(h, "2", `ACME\sam`, true)
	h.AddView(v)
	updates, err := h.Request(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h, v, updates)
	return h, v, sent, updates
}

func planStateSent(sent func() []Envelope, accessID, digest, state string) *PlanStateView {
	for _, e := range sent() {
		if e.Type == TypePlanState && e.PlanState.AccessID == accessID && e.PlanState.Digest == digest && e.PlanState.State == state {
			return e.PlanState
		}
	}
	return nil
}

// waitPlanState waits for a window to be told a review moved to state. Some
// endings run from the hub's own goroutines.
func waitPlanState(t *testing.T, sent func() []Envelope, accessID, digest, state string) PlanStateView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if pv := planStateSent(sent, accessID, digest, state); pv != nil {
			return *pv
		}
		if time.Now().After(deadline) {
			t.Fatalf("the window was never told the review of %s/%s is %s", accessID, digest, state)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// ReviewChange never blocks: it shows the plan, including who prepared it and
// why, and returns before anyone has answered.
func TestHubReviewChangeReturnsAtOnceAndShowsThePlan(t *testing.T) {
	h, _, sent, _ := liveGrant(t, context.Background())
	ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d, ok := <-ch:
		t.Fatalf("a review nobody has answered yet produced %+v, %v", d, ok)
	default:
	}
	var got *PlanView
	for _, e := range sent() {
		if e.Type == TypePlan && e.Plan.Digest == "digest_one" {
			got = e.Plan
		}
	}
	if got == nil {
		t.Fatal("the plan was not shown")
	}
	if got.AccessID != "acc_one" || got.Path != `C:\Vendor\config.ini` || got.Diff == "" ||
		got.Reason != "fix the vendor config" || got.Technician != "alice" {
		t.Fatalf("plan shown: %+v", got)
	}
}

// An elevated window may approve a change: the review ends with one decision
// naming who approved and which digest, and a second answer is refused.
func TestHubApprovesAChangeWithAnElevatedWindow(t *testing.T) {
	h, v, sent, _ := liveGrant(t, context.Background())
	ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideApprove}); err != nil {
		t.Fatal(err)
	}
	d, ok := <-ch
	if !ok {
		t.Fatal("the review channel closed with no decision")
	}
	if d.State != proto.ConsentApproved || d.Approver != `ACME\sam` || d.PlanDigest != "digest_one" {
		t.Fatalf("plan approval = %+v", d)
	}
	if _, ok := <-ch; ok {
		t.Fatal("the review channel yielded a second value")
	}
	if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanApproved); pv.Approver != `ACME\sam` {
		t.Fatalf("plan_state approved: %+v", pv)
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideDeny}); err == nil {
		t.Fatal("a second decision on an already-answered review was accepted")
	}
}

// Denying a change is reducing access, so it needs no elevation.
func TestHubUnelevatedDenyIsAccepted(t *testing.T) {
	h, _, sent, _ := liveGrant(t, context.Background())
	plain, _ := view(h, "2", `ACME\sam`, false)
	h.AddView(plain)
	ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DecidePlan(plain, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideDeny}); err != nil {
		t.Fatal(err)
	}
	d, ok := <-ch
	if !ok || d.State != proto.ConsentDenied || d.Approver != `ACME\sam` {
		t.Fatalf("unelevated deny = %+v, %v", d, ok)
	}
	if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanDenied); pv.Approver != `ACME\sam` {
		t.Fatalf("plan_state denied: %+v", pv)
	}
}

// An unelevated approval is refused without ending the review, so the same
// window, once elevated, or another elevated window, can still approve it.
func TestHubUnelevatedApproveIsRefusedThenElevatedApproveSucceeds(t *testing.T) {
	h, v, _, _ := liveGrant(t, context.Background())
	plain, _ := view(h, "2", `ACME\sam`, false)
	h.AddView(plain)
	ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DecidePlan(plain, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideApprove}); err == nil {
		t.Fatal("an unelevated window approved a change")
	}
	select {
	case d, ok := <-ch:
		t.Fatalf("a refused approval ended the review: %+v, %v", d, ok)
	default:
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideApprove}); err != nil {
		t.Fatal(err)
	}
	d, ok := <-ch
	if !ok || d.State != proto.ConsentApproved {
		t.Fatalf("elevated approve after the refusal = %+v, %v", d, ok)
	}
}

// A review that outlasts its ctx ends undecided, and a decision that arrives
// afterward is refused.
func TestHubReviewEndsAtItsDeadline(t *testing.T) {
	h, v, sent, _ := liveGrant(t, context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ch, err := h.ReviewChange(ctx, reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d, ok := <-ch:
		if ok {
			t.Fatalf("an expired review produced a decision: %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the review channel did not close at its deadline")
	}
	if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanEnded); pv.Reason == "" {
		t.Fatalf("plan_state ended: %+v", pv)
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideApprove}); err == nil {
		t.Fatal("a decision after the deadline was accepted")
	}
}

// A review cannot outlive the grant it belongs to: the endpoint user ending
// it, or the runner ending the request, both end any pending review the same
// way — undecided, and refusing any decision that arrives after.
func TestHubReviewEndsWhenTheGrantEnds(t *testing.T) {
	t.Run("the endpoint user terminates the grant", func(t *testing.T) {
		h, v, sent, updates := liveGrant(t, context.Background())
		ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Control(v, Control{AccessID: "acc_one", Action: ControlEnd}); err != nil {
			t.Fatal(err)
		}
		d, ok := <-ch
		if ok {
			t.Fatalf("a terminated grant's review produced a decision: %+v", d)
		}
		if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanEnded); pv.Reason == "" {
			t.Fatalf("plan_state ended: %+v", pv)
		}
		if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideDeny}); err == nil {
			t.Fatal("a decision after the grant was terminated was accepted")
		}
		closed(t, updates)
	})
	t.Run("the runner ends the request", func(t *testing.T) {
		ctx, end := context.WithCancelCause(context.Background())
		h, v, sent, _ := liveGrant(t, ctx)
		ch, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
		if err != nil {
			t.Fatal(err)
		}
		end(errors.New(proto.ReasonTechnician))
		d, ok := <-ch
		if ok {
			t.Fatalf("a review of an ended request produced a decision: %+v", d)
		}
		if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanEnded); pv.Reason == "" {
			t.Fatalf("plan_state ended: %+v", pv)
		}
		if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideDeny}); err == nil {
			t.Fatal("a decision after the request ended was accepted")
		}
	})
}

// A second review for the same access ID replaces the first: the old one
// ends, undecided, and a decision naming its digest is refused.
func TestHubANewReviewReplacesThePending(t *testing.T) {
	h, v, sent, _ := liveGrant(t, context.Background())
	ch1, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one"))
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_two"))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := <-ch1
	if ok {
		t.Fatalf("the replaced review produced a decision: %+v", d)
	}
	if pv := waitPlanState(t, sent, "acc_one", "digest_one", PlanEnded); pv.Reason == "" {
		t.Fatalf("plan_state ended for the replaced review: %+v", pv)
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_one", Decision: DecideDeny}); err == nil {
		t.Fatal("a decision naming the replaced digest was accepted")
	}
	if err := h.DecidePlan(v, PlanDecision{AccessID: "acc_one", Digest: "digest_two", Decision: DecideApprove}); err != nil {
		t.Fatal(err)
	}
	d2, ok := <-ch2
	if !ok || d2.PlanDigest != "digest_two" {
		t.Fatalf("the replacing review = %+v, %v", d2, ok)
	}
}

// A window that connects after the review started is shown the plan too.
func TestHubShowsAPendingReviewToAViewThatConnectsLate(t *testing.T) {
	h, _, _, _ := liveGrant(t, context.Background())
	if _, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one")); err != nil {
		t.Fatal(err)
	}
	late, lateSent := view(h, "2", `ACME\sam`, true)
	h.AddView(late)
	if !slices.ContainsFunc(lateSent(), func(e Envelope) bool {
		return e.Type == TypePlan && e.Plan.AccessID == "acc_one" && e.Plan.Digest == "digest_one"
	}) {
		t.Fatal("the late window was not shown the pending review")
	}
}

// ReviewChange refuses to start without something that could answer it: no
// request on file, a request nobody has approved yet, or one no window is
// watching.
func TestHubReviewChangeRequiresALiveRequestAndAWindow(t *testing.T) {
	h := NewHub(HubOptions{})
	if _, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one")); err == nil {
		t.Fatal("a review started with no request on file")
	}
	v, _ := view(h, "2", `ACME\sam`, true)
	h.AddView(v)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one")); err == nil {
		t.Fatal("a review started on an undecided request")
	}
	approve(t, h, v, updates)
	h.RemoveView(v, false) // the last window goes; nothing is left to watch it
	if _, err := h.ReviewChange(context.Background(), reviewRequest(t, "acc_one", "digest_one")); err == nil {
		t.Fatal("a review started with no window watching")
	}
}

// A plan that does not decode, or whose digest does not match what the
// request claims, is refused before anything is shown.
func TestHubReviewChangeRejectsAMalformedOrMismatchedPlan(t *testing.T) {
	h, _, _, _ := liveGrant(t, context.Background())
	if _, err := h.ReviewChange(context.Background(),
		proto.ConsentRequest{AccessID: "acc_one", PlanDigest: "digest_one", Plan: []byte("not json")}); err == nil {
		t.Fatal("malformed plan JSON was accepted")
	}
	mismatched := reviewRequest(t, "acc_one", "digest_one")
	mismatched.PlanDigest = "digest_two" // does not match the encoded plan's own digest
	if _, err := h.ReviewChange(context.Background(), mismatched); err == nil {
		t.Fatal("a digest that does not match the plan was accepted")
	}
	empty := reviewRequest(t, "acc_one", "digest_one")
	empty.AccessID = ""
	if _, err := h.ReviewChange(context.Background(), empty); err == nil {
		t.Fatal("an empty access ID was accepted")
	}
}

func TestHubSaysWhenNobodyIsSignedIn(t *testing.T) {
	h := NewHub(HubOptions{Sessions: func() []string { return nil }})
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if u := next(t, updates); u.State != proto.ConsentAwaiting || u.Reason != proto.ReasonNoUser {
		t.Fatalf("unattended request: %+v", u)
	}
	// Someone signs in before the window closes: the request is shown and no
	// longer waiting on a user.
	v, sent := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	if u := next(t, updates); u.State != proto.ConsentAwaiting || u.Reason != "" {
		t.Fatalf("request after sign-in: %+v", u)
	}
	if !slices.ContainsFunc(sent(), func(e Envelope) bool { return e.Type == TypeRequest }) {
		t.Fatal("the request was not shown to the session that signed in")
	}
}

// A locked desktop is still a session with a signed-in user. The request is
// shown there and waits; nothing says nobody is signed in, so the refusal at
// the endpoint's deadline says timeout, not no_user.
func TestHubLockedDesktopKeepsWaiting(t *testing.T) {
	var launched []string
	h := NewHub(HubOptions{Sessions: func() []string { return []string{"1"} },
		Launch: func(s string) error { launched = append(launched, s); return nil }})
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(launched, []string{"1"}) {
		t.Fatalf("consent window started in %v, want session 1", launched)
	}
	// present runs inside Request, so a no_user report would already be queued.
	if len(updates) != 0 {
		t.Fatalf("a locked session was reported as unattended: %+v", <-updates)
	}
}

// The last user signing out with a request still undecided is the same as
// nobody having been signed in.
func TestHubLastSignOutLeavesARequestUnattended(t *testing.T) {
	var s signedIn
	s.set("2")
	h := NewHub(HubOptions{Sessions: s.get})
	v, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	s.set()
	h.RemoveView(v, true)
	if u := next(t, updates); u.State != proto.ConsentAwaiting || u.Reason != proto.ReasonNoUser {
		t.Fatalf("request after the last sign-out: %+v", u)
	}
}

func TestHubStopsGrantsWhenTheWindowGoes(t *testing.T) {
	h := NewHub(HubOptions{})
	v, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h, v, updates)
	// The application exits but the session is still signed in: the runner
	// sees the conversation end, which pauses the grant.
	h.RemoveView(v, false)
	if _, ok := <-updates; ok {
		t.Fatal("the conversation stayed open after the last window closed")
	}

	// The approver signing out ends the grant outright.
	h2 := NewHub(HubOptions{})
	v2, _ := view(h2, "2", "ACME\\sam", true)
	h2.AddView(v2)
	updates2, err := h2.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h2, v2, updates2)
	h2.RemoveView(v2, true)
	if u := next(t, updates2); u.State != proto.ConsentTerminated || u.Reason != proto.ReasonLogoff {
		t.Fatalf("sign-out: %+v", u)
	}
}

// A sign-out that no window of the approver's was open to see still ends
// their grant: when the grant is shown again after its window crashed, and
// while another session's window is watching it.
func TestHubEndsAGrantWhoseApproverSignedOutUnseen(t *testing.T) {
	t.Run("after the window crashed", func(t *testing.T) {
		var s signedIn
		s.set("2")
		h := NewHub(HubOptions{Sessions: s.get, SessionPoll: time.Millisecond})
		v, _ := view(h, "2", "ACME\\sam", true)
		h.AddView(v)
		updates, err := h.Request(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}
		approve(t, h, v, updates)
		h.RemoveView(v, false) // the window crashes; the runner pauses the grant
		closed(t, updates)
		s.set()                                                      // the user signs out with no window open
		again, err := h.Request(context.Background(), testRequest()) // the runner shows the grant again
		if err != nil {
			t.Fatal(err)
		}
		if u := next(t, again); u.State != proto.ConsentTerminated || u.Reason != proto.ReasonLogoff {
			t.Fatalf("grant of a signed-out approver: %+v", u)
		}
	})
	t.Run("while another session watches", func(t *testing.T) {
		var s signedIn
		s.set("2", "3")
		h := NewHub(HubOptions{Sessions: s.get, SessionPoll: time.Millisecond})
		approver, _ := view(h, "2", "ACME\\sam", true)
		other, otherSent := view(h, "3", "ACME\\kim", false)
		h.AddView(approver)
		h.AddView(other)
		updates, err := h.Request(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}
		approve(t, h, approver, updates)
		h.RemoveView(approver, false) // crashes; session 3 still watches, so nothing pauses
		if len(updates) != 0 {
			t.Fatalf("a watched grant changed when one window went: %+v", <-updates)
		}
		s.set("3")
		if u := next(t, updates); u.State != proto.ConsentTerminated || u.Reason != proto.ReasonLogoff {
			t.Fatalf("grant after its approver signed out: %+v", u)
		}
		if sv := waitState(t, otherSent, "acc_one", proto.ConsentTerminated); sv.Reason != proto.ReasonLogoff {
			t.Fatalf("the watching window was told %+v", sv)
		}
	})
}

func TestHubPauseResumeAndTerminate(t *testing.T) {
	h := NewHub(HubOptions{})
	v, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	updates, err := h.Request(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h, v, updates)
	plain, _ := view(h, "2", "ACME\\sam", false) // pausing needs no elevation
	h.AddView(plain)
	if err := h.Control(plain, Control{AccessID: "acc_one", Action: ControlResume}); err == nil {
		t.Fatal("a grant that is not paused was resumed")
	}
	if err := h.Control(plain, Control{AccessID: "acc_one", Action: ControlPause}); err != nil {
		t.Fatal(err)
	}
	if u := next(t, updates); u.State != proto.ConsentPaused || u.Reason != proto.ReasonUser {
		t.Fatalf("pause: %+v", u)
	}
	if err := h.Control(plain, Control{AccessID: "acc_one", Action: ControlPause}); err != nil {
		t.Fatal(err)
	}
	if len(updates) != 0 {
		t.Fatalf("pausing twice was reported twice: %+v", <-updates)
	}
	if err := h.Control(plain, Control{AccessID: "acc_one", Action: ControlResume}); err != nil {
		t.Fatal(err)
	}
	if u := next(t, updates); u.State != proto.ConsentApproved || u.Reason != proto.ReasonUser {
		t.Fatalf("resume: %+v", u)
	}
	if err := h.Control(plain, Control{AccessID: "acc_one", Action: ControlEnd}); err != nil {
		t.Fatal(err)
	}
	if u := next(t, updates); u.State != proto.ConsentTerminated || u.Reason != proto.ReasonUser {
		t.Fatalf("terminate: %+v", u)
	}
}

// A grant shown again after the consent application came back keeps what the
// user already granted, rather than asking a second time.
func TestHubReshowKeepsTheGrant(t *testing.T) {
	h := NewHub(HubOptions{})
	v, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	cr := testRequest()
	updates, err := h.Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Decide(v, Decision{AccessID: cr.AccessID, Decision: DecideApprove, Select: []int{0}}); err != nil {
		t.Fatal(err)
	}
	next(t, updates)
	h.RemoveView(v, false)
	closed(t, updates)

	again, err := h.Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := view(h, "2", "ACME\\sam", false)
	h.AddView(back) // a window watching again lifts the pause by itself
	h.Resume(cr.AccessID)
	u := next(t, again)
	if u.State != proto.ConsentApproved || u.Approver != "ACME\\sam" || len(u.Paths) != 1 || u.Paths[0] != cr.Paths[0] ||
		u.Reason != proto.ReasonUIRestored {
		t.Fatalf("reshown grant: %+v", u)
	}
	if len(again) != 0 {
		t.Fatalf("the grant was resumed twice: %+v", <-again)
	}
	if got := h.Requests(); len(got) != 1 || got[0].State != proto.ConsentNarrowed {
		t.Fatalf("requests after reshow: %+v", got)
	}
}

// A pause the endpoint user chose is theirs to lift. The window crashing and
// coming back, or another window attaching, does not resume it.
func TestHubUserPauseSurvivesAWindowReturning(t *testing.T) {
	h := NewHub(HubOptions{})
	v, _ := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	cr := testRequest()
	updates, err := h.Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h, v, updates)
	if err := h.Control(v, Control{AccessID: cr.AccessID, Action: ControlPause}); err != nil {
		t.Fatal(err)
	}
	next(t, updates)
	h.RemoveView(v, false)
	closed(t, updates)

	again, err := h.Request(context.Background(), cr)
	if err != nil {
		t.Fatal(err)
	}
	back, sent := view(h, "2", "ACME\\sam", false)
	h.AddView(back)
	h.Resume(cr.AccessID) // what a transport might do for a grant paused for want of a window
	if len(again) != 0 {
		t.Fatalf("a pause the user chose was lifted by a window returning: %+v", <-again)
	}
	if !slices.ContainsFunc(sent(), func(e Envelope) bool {
		return e.Type == TypeRequest && e.Request.AccessID == cr.AccessID && e.Request.State == proto.ConsentPaused
	}) {
		t.Fatal("the returning window was not shown the paused grant")
	}
	if err := h.Control(back, Control{AccessID: cr.AccessID, Action: ControlResume}); err != nil {
		t.Fatal(err)
	}
	if u := next(t, again); u.State != proto.ConsentApproved || u.Reason != proto.ReasonUser {
		t.Fatalf("resumed by the user: %+v", u)
	}
}

// When the runner is finished with a request — the technician ended it, it
// expired — every window is told why, and nothing on screen can act on it.
func TestHubClosesARequestTheRunnerEnded(t *testing.T) {
	h := NewHub(HubOptions{})
	v, sent := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	ctx, end := context.WithCancelCause(context.Background())
	updates, err := h.Request(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	approve(t, h, v, updates)
	end(errors.New(proto.ReasonTechnician))
	if sv := waitState(t, sent, "acc_one", proto.ConsentTerminated); sv.Reason != proto.ReasonTechnician {
		t.Fatalf("the window was told %+v", sv)
	}
	if err := h.Control(v, Control{AccessID: "acc_one", Action: ControlPause}); err == nil {
		t.Fatal("a window could still pause an ended grant")
	}
	if got := h.Requests(); len(got) != 0 {
		t.Fatalf("the hub still holds %+v", got)
	}
}

// An undecided request the endpoint refused at its own deadline is withdrawn
// from every window, and an answer given afterwards is refused rather than
// shown as an approval nobody will honour.
func TestHubWithdrawsARequestRefusedAtTheDeadline(t *testing.T) {
	h := NewHub(HubOptions{})
	v, sent := view(h, "2", "ACME\\sam", true)
	h.AddView(v)
	ctx, end := context.WithCancelCause(context.Background())
	updates, err := h.Request(ctx, testRequest())
	if err != nil {
		t.Fatal(err)
	}
	end(errors.New(proto.ReasonTimeout))
	if sv := waitState(t, sent, "acc_one", proto.ConsentDenied); sv.Reason != proto.ReasonTimeout {
		t.Fatalf("the window was told %+v", sv)
	}
	if err := h.Decide(v, Decision{AccessID: "acc_one", Decision: DecideApprove}); err == nil {
		t.Fatal("a request refused at the deadline accepted a late approval")
	}
	if stateSent(sent, "acc_one", proto.ConsentApproved) != nil {
		t.Fatal("the window was told a refused request was approved")
	}
	closed(t, updates)
}

// The protocol grows additively: a message type or field a peer does not
// know decodes cleanly and is left for the peer to ignore.
func TestEnvelopeToleratesAdditions(t *testing.T) {
	r := NewReader(strings.NewReader(`{"type":"plan_review","plan":{"digest":"sha256:ab"},"future":1}` + "\n"))
	e, err := ReadEnvelope(r)
	if err != nil || e.Type != "plan_review" || e.Request != nil || e.Decide != nil {
		t.Fatalf("an envelope from a newer peer: %+v, %v", e, err)
	}
}

func TestEnvelopeRoundTripAndLimits(t *testing.T) {
	var buf bytes.Buffer
	rv := RequestView{AccessID: "acc_one", Paths: []string{`C:\x`}}
	if err := WriteEnvelope(&buf, Envelope{Type: TypeRequest, Request: &rv}); err != nil {
		t.Fatal(err)
	}
	if err := WriteEnvelope(&buf, Envelope{Type: TypeDecide, Decide: &Decision{AccessID: "acc_one", Decision: DecideDeny}}); err != nil {
		t.Fatal(err)
	}
	r := NewReader(&buf)
	first, err := ReadEnvelope(r)
	if err != nil || first.Type != TypeRequest || first.Request.AccessID != "acc_one" {
		t.Fatalf("first message: %+v, %v", first, err)
	}
	second, err := ReadEnvelope(r)
	if err != nil || second.Type != TypeDecide || second.Decide.Decision != DecideDeny {
		t.Fatalf("second message: %+v, %v", second, err)
	}
	huge := NewReader(strings.NewReader(strings.Repeat("x", MaxMessageBytes+10) + "\n"))
	if _, err := ReadEnvelope(huge); err == nil {
		t.Fatal("an oversized message was accepted")
	}
}
