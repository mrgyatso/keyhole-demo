package e2e_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/consentipc"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// desktop stands in for Windows on the endpoint: which sessions have a
// signed-in user, where the service started the consent window, and the
// windows attached to the service's pipe. Everything else is the real code:
// the service's consent hub, the runner, the relay and the gateway. The pipe
// and the peer checks that feed the hub are Windows-only; the consentipc
// test executable exercises them on the laptop.
type desktop struct {
	mu       sync.Mutex
	signedIn []string
	launched map[string]int
	hub      *consentipc.Hub
}

func newDesktop(sessions ...string) *desktop {
	return &desktop{signedIn: sessions, launched: map[string]int{}}
}

// service builds the consent transport a (re)started service would.
func (d *desktop) service() agent.ConsentAdapter {
	h := consentipc.NewHub(consentipc.HubOptions{Sessions: d.sessions, Launch: d.launch,
		SessionPoll: 10 * time.Millisecond})
	d.mu.Lock()
	d.hub = h
	d.mu.Unlock()
	return h
}

func (d *desktop) sessions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.signedIn)
}

func (d *desktop) setSignedIn(sessions ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signedIn = slices.Clone(sessions)
}

func (d *desktop) launch(session string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.launched[session]++
	return nil
}

func (d *desktop) launches(session string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.launched[session]
}

// waitLaunch waits until the service has started the consent window in
// session more than n times.
func (d *desktop) waitLaunch(t *testing.T, session string, n int) {
	t.Helper()
	waitFor(t, "the consent window to be started in session "+session, func() bool { return d.launches(session) > n })
}

// window is one consent window attached to the service, identified the way
// the pipe server identifies a verified peer.
type window struct {
	hub *consentipc.Hub
	v   *consentipc.View
	mu  sync.Mutex
	got []consentipc.Envelope
}

func (d *desktop) open(session, user string, elevated bool) *window {
	d.mu.Lock()
	h := d.hub
	d.mu.Unlock()
	w := &window{hub: h}
	w.v = &consentipc.View{Session: session, User: user, Elevated: elevated, Send: func(e consentipc.Envelope) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.got = append(w.got, e)
	}}
	h.AddView(w.v)
	return w
}

// signOut is the user of w's session signing out: the session loses its
// user and the window's pipe closes with it.
func (d *desktop) signOut(w *window) {
	d.mu.Lock()
	d.signedIn = slices.DeleteFunc(d.signedIn, func(s string) bool { return s == w.v.Session })
	d.mu.Unlock()
	w.hub.RemoveView(w.v, true)
}

// crash is the window's process dying while its session stays signed in.
func (w *window) crash() { w.hub.RemoveView(w.v, false) }

// leave closes a window a subtest has finished with.
func (w *window) leave() { w.hub.RemoveView(w.v, false) }

func (w *window) sees(t *testing.T, what string, match func(consentipc.Envelope) bool) consentipc.Envelope {
	t.Helper()
	var found consentipc.Envelope
	waitFor(t, what, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, e := range w.got {
			if match(e) {
				found = e
				return true
			}
		}
		return false
	})
	return found
}

func (w *window) seesRequest(t *testing.T, accessID string) consentipc.RequestView {
	t.Helper()
	return *w.sees(t, "request "+accessID+" on screen", func(e consentipc.Envelope) bool {
		return e.Type == consentipc.TypeRequest && e.Request.AccessID == accessID
	}).Request
}

func (w *window) seesState(t *testing.T, accessID, state string) consentipc.StateView {
	t.Helper()
	return *w.sees(t, accessID+" shown as "+state, func(e consentipc.Envelope) bool {
		return e.Type == consentipc.TypeState && e.State.AccessID == accessID && e.State.State == state
	}).State
}

func (w *window) approve(accessID string, sel ...int) error {
	return w.hub.Decide(w.v, consentipc.Decision{AccessID: accessID, Decision: consentipc.DecideApprove, Select: sel})
}

func (w *window) deny(accessID, reason string) error {
	return w.hub.Decide(w.v, consentipc.Decision{AccessID: accessID, Decision: consentipc.DecideDeny, Reason: reason})
}

func (w *window) control(accessID, action string) error {
	return w.hub.Control(w.v, consentipc.Control{AccessID: accessID, Action: action})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestConsentWindowRulesEndToEnd holds each of Slice 3's completion cases
// against the service's real consent hub, the runner, the relay and the
// gateway. Only the Windows sessions and the windows themselves are
// simulated, and the endpoint's consent window is shortened to
// consentWindow as in the other consent tests.
func TestConsentWindowRulesEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d := newDesktop("1")
	s := newStackWith(t, ctx, d.service)
	readOK := func(t *testing.T, id string) {
		t.Helper()
		if text, bad := s.read(id); bad || !strings.Contains(text, "acme operational log") {
			t.Fatalf("read under %s: %s", id, text)
		}
	}
	readRefused := func(t *testing.T, id string) {
		t.Helper()
		if text, bad := s.read(id); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("read under %s was not refused: %s", id, text)
		}
	}
	reason := func(t *testing.T, got model.AccessRequest, want string) {
		t.Helper()
		if got.Reason != want {
			t.Fatalf("%s is %s because %q, want %q", got.ID, got.State, got.Reason, want)
		}
	}
	// grant opens an elevated window in session 1 and approves a new request
	// from it.
	grant := func(t *testing.T, purpose string) (model.AccessRequest, *window) {
		t.Helper()
		w := d.open("1", `ACME\sam`, true)
		a := s.request(purpose)
		w.seesRequest(t, a.ID)
		if err := w.approve(a.ID); err != nil {
			t.Fatal(err)
		}
		s.status(a.ID, model.AccessApproved)
		return a, w
	}
	end := func(t *testing.T, w *window, id string) {
		t.Helper()
		if err := w.control(id, consentipc.ControlEnd); err != nil {
			t.Fatal(err)
		}
		reason(t, s.status(id, model.AccessTerminated), proto.ReasonUser)
	}

	t.Run("no user signed in", func(t *testing.T) {
		d.setSignedIn()
		defer d.setSignedIn("1")
		a := s.request("unattended diagnostics")
		reason(t, s.status(a.ID, model.AccessDenied), proto.ReasonNoUser)
		readRefused(t, a.ID)
	})

	t.Run("locked desktop keeps waiting, then is refused at the deadline", func(t *testing.T) {
		// The window started at logon is attached, but the desktop is locked
		// and nobody answers. The request waits, is refused at the endpoint's
		// deadline, and the window stops offering it.
		w := d.open("1", `ACME\sam`, true)
		defer w.leave()
		a := s.request("locked diagnostics")
		w.seesRequest(t, a.ID)
		reason(t, s.status(a.ID, model.AccessDenied), proto.ReasonTimeout)
		if sv := w.seesState(t, a.ID, proto.ConsentDenied); sv.Reason != proto.ReasonTimeout {
			t.Fatalf("the window was told %+v", sv)
		}
		// Unlocking and answering afterwards changes nothing.
		if err := w.approve(a.ID); err == nil {
			t.Fatal("a request refused at the deadline accepted a late approval")
		}
		readRefused(t, a.ID)
	})

	t.Run("signed in with no window, nobody answers", func(t *testing.T) {
		before := d.launches("1")
		a := s.request("windowless diagnostics")
		d.waitLaunch(t, "1", before) // the service starts the window in the session
		reason(t, s.status(a.ID, model.AccessDenied), proto.ReasonTimeout)
	})

	t.Run("approving needs an elevated window", func(t *testing.T) {
		plain := d.open("1", `ACME\sam`, false)
		defer plain.leave()
		a := s.request("elevation diagnostics")
		plain.seesRequest(t, a.ID)
		if err := plain.approve(a.ID); err == nil {
			t.Fatal("a window without an elevated token approved a request")
		}
		// Approving relaunches the window through UAC; the elevated copy
		// answers and exits.
		elevated := d.open("1", `ACME\sam`, true)
		if err := elevated.approve(a.ID); err != nil {
			t.Fatal(err)
		}
		elevated.leave()
		got := s.status(a.ID, model.AccessApproved)
		if got.Approver != `ACME\sam` || got.ApproverSession != "1" {
			t.Fatalf("approver %q in session %q", got.Approver, got.ApproverSession)
		}
		plain.seesState(t, a.ID, proto.ConsentApproved)
		readOK(t, a.ID)
		end(t, plain, a.ID) // ending needs no elevation
	})

	t.Run("narrow", func(t *testing.T) {
		w := d.open("1", `ACME\sam`, true)
		defer w.leave()
		a := s.request("narrow diagnostics", s.root, filepath.Dir(s.root))
		w.seesRequest(t, a.ID)
		if err := w.approve(a.ID, 0); err != nil {
			t.Fatal(err)
		}
		got := s.status(a.ID, model.AccessApproved)
		if !slices.Equal(got.EffectiveScope, []string{s.root}) {
			t.Fatalf("effective scope %v", got.EffectiveScope)
		}
		readOK(t, a.ID)
		end(t, w, a.ID)
	})

	t.Run("two sessions: the first answer wins", func(t *testing.T) {
		d.setSignedIn("1", "2")
		defer d.setSignedIn("1")
		first, second := d.open("1", `ACME\sam`, true), d.open("2", `ACME\kim`, true)
		defer second.leave()
		a := s.request("multi-session diagnostics")
		first.seesRequest(t, a.ID)
		second.seesRequest(t, a.ID)
		if err := second.approve(a.ID); err != nil {
			t.Fatal(err)
		}
		if err := first.deny(a.ID, "too late"); err != nil {
			t.Fatal(err) // ignored, not an error
		}
		got := s.status(a.ID, model.AccessApproved)
		if got.Approver != `ACME\kim` || got.ApproverSession != "2" {
			t.Fatalf("a later answer overrode the first: %+v", got)
		}
		first.seesState(t, a.ID, proto.ConsentApproved)
		// The session that did not approve signing out changes nothing.
		d.signOut(first)
		readOK(t, a.ID)
		end(t, second, a.ID)
	})

	t.Run("pause and resume from the window", func(t *testing.T) {
		a, w := grant(t, "pause diagnostics")
		defer w.leave()
		readOK(t, a.ID)
		if err := w.control(a.ID, consentipc.ControlPause); err != nil {
			t.Fatal(err)
		}
		reason(t, s.status(a.ID, model.AccessPaused), proto.ReasonUser)
		readRefused(t, a.ID)
		if err := w.control(a.ID, consentipc.ControlResume); err != nil {
			t.Fatal(err)
		}
		s.status(a.ID, model.AccessApproved)
		readOK(t, a.ID)
		end(t, w, a.ID)
	})

	t.Run("consent window crash pauses the grant until a window is back", func(t *testing.T) {
		a, w := grant(t, "crash diagnostics")
		readOK(t, a.ID)
		before := d.launches("1")
		w.crash()
		reason(t, s.status(a.ID, model.AccessPaused), proto.ReasonUIGone)
		readRefused(t, a.ID)
		// The service starts the window again. The copy started at logon is
		// not elevated and does not need to be: watching is not approving.
		d.waitLaunch(t, "1", before)
		back := d.open("1", `ACME\sam`, false)
		defer back.leave()
		got := s.status(a.ID, model.AccessApproved)
		if got.Reason != proto.ReasonUIRestored || got.Approver != `ACME\sam` {
			t.Fatalf("resumed grant: %+v", got)
		}
		readOK(t, a.ID)
		end(t, back, a.ID)
	})

	t.Run("a pause the user chose survives the window coming back", func(t *testing.T) {
		a, w := grant(t, "held diagnostics")
		if err := w.control(a.ID, consentipc.ControlPause); err != nil {
			t.Fatal(err)
		}
		s.status(a.ID, model.AccessPaused)
		before := d.launches("1")
		w.crash()
		d.waitLaunch(t, "1", before)
		back := d.open("1", `ACME\sam`, false)
		defer back.leave()
		if rv := back.seesRequest(t, a.ID); rv.State != proto.ConsentPaused {
			t.Fatalf("the returning window was shown the grant as %s", rv.State)
		}
		readRefused(t, a.ID)
		if err := back.control(a.ID, consentipc.ControlResume); err != nil {
			t.Fatalf("the user could not resume their own pause: %v", err)
		}
		reason(t, s.status(a.ID, model.AccessApproved), proto.ReasonUser)
		readOK(t, a.ID)
		end(t, back, a.ID)
	})

	t.Run("signing out ends the grant", func(t *testing.T) {
		a, w := grant(t, "logoff diagnostics")
		defer d.setSignedIn("1")
		d.signOut(w)
		reason(t, s.status(a.ID, model.AccessTerminated), proto.ReasonLogoff)
		readRefused(t, a.ID)
	})

	t.Run("signing out after the window crashed still ends the grant", func(t *testing.T) {
		a, w := grant(t, "crash then logoff diagnostics")
		defer d.setSignedIn("1")
		w.crash()
		s.status(a.ID, model.AccessPaused)
		d.setSignedIn() // no window of the user's is left to see it
		reason(t, s.status(a.ID, model.AccessTerminated), proto.ReasonLogoff)
		readRefused(t, a.ID)
	})

	t.Run("the technician ending access closes it on screen", func(t *testing.T) {
		a, w := grant(t, "withdrawn diagnostics")
		defer w.leave()
		if text, bad := s.call(proto.OpEndAccess, map[string]any{"access_id": a.ID}); bad {
			t.Fatalf("end_access: %s", text)
		}
		if sv := w.seesState(t, a.ID, proto.ConsentTerminated); sv.Reason != proto.ReasonTechnician {
			t.Fatalf("the window was told %+v", sv)
		}
		if err := w.control(a.ID, consentipc.ControlPause); err == nil {
			t.Fatal("the window could still act on an ended grant")
		}
	})

	t.Run("service restart ends live grants", func(t *testing.T) {
		a, _ := grant(t, "restart diagnostics")
		readOK(t, a.ID)
		s.restart() // the window's pipe goes with the old service
		reason(t, s.status(a.ID, model.AccessTerminated), proto.ReasonRestart)
		readRefused(t, a.ID)
	})
}
