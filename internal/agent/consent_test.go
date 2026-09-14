package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/agent/consentscript"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/proto"
)

func consentRunner(adapter ConsentAdapter) *Runner {
	e := &Enrollment{Client: "acme", DeviceID: "dev_one"}
	work, cancel := context.WithCancel(context.Background())
	return &Runner{o: RunnerOptions{Enrollment: e, Host: hostinfo.Info{OS: runtime.GOOS}, Consent: adapter, ConsentWindow: 100 * time.Millisecond},
		log: slog.New(slog.DiscardHandler), deviceID: e.DeviceID, grants: grantCache{grants: map[string]liveGrant{}},
		work: work, cancelWork: cancel}
}

func consentRequest() proto.ConsentRequest {
	// An absolute path in the endpoint's own syntax, so these tests also run
	// on the Windows laptop (agent.test.exe).
	root := filepath.Join(string(filepath.Separator), "logs")
	if runtime.GOOS == "windows" {
		root = `C:\logs`
	}
	return proto.ConsentRequest{AccessID: "acc_one", Client: "acme", Device: "dev_one", Technician: "alice",
		Purpose: "diagnose", Operations: []string{proto.OpReadFile}, Paths: []string{root},
		Duration: time.Minute, IdleTimeout: time.Minute}
}

// ack runs one request_access and checks that the endpoint only acknowledges
// it: the decision is asynchronous now.
func ack(t *testing.T, r *Runner, cr proto.ConsentRequest) {
	t.Helper()
	resp := r.consent(context.Background(), cr)
	if resp.Error != nil {
		t.Fatal(resp.Error)
	}
	var d proto.ConsentDecision
	if err := json.Unmarshal(resp.Result, &d); err != nil {
		t.Fatal(err)
	}
	if d.State != proto.ConsentAwaiting || d.Capability != nil {
		t.Fatalf("request_access answered %q with capability %v; want an acknowledgement only", d.State, d.Capability)
	}
}

// waitGrant waits for the live grant cache to reach state.
func waitGrant(t *testing.T, r *Runner, accessID, state string) liveGrant {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.grants.mu.Lock()
		g, ok := r.grants.grants[accessID]
		r.grants.mu.Unlock()
		switch {
		case ok && g.state == state:
			return g
		case state == "" && !ok:
			return liveGrant{}
		case time.Now().After(deadline):
			t.Fatalf("grant %s is %q, want %q (present: %t)", accessID, g.state, state, ok)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestEndpointCapabilityBindingsAndTermination(t *testing.T) {
	script := consentscript.New()
	r := consentRunner(script)
	cr := consentRequest()
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Approve("local-user")
	cap := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap

	base := proto.Request{Op: proto.OpReadFile, Caller: proto.Caller{Tech: "alice"}, Capability: &cap, Policy: proto.Policy{}}
	if err := r.authorize(&base); err != nil {
		t.Fatalf("approved grant: %v", err)
	}
	checks := []func(*proto.Capability){
		func(c *proto.Capability) { c.Device = "dev_other" },
		func(c *proto.Capability) { c.Client = "globex" },
		func(c *proto.Capability) { c.Technician = "bob" },
		func(c *proto.Capability) { c.Nonce = "replayed" },
		func(c *proto.Capability) { c.Paths = []string{filepath.Dir(c.Paths[0])} },
		func(c *proto.Capability) { c.ExpiresAt = time.Now().Add(-time.Second) },
	}
	for i, mutate := range checks {
		c := cap
		mutate(&c)
		req := base
		req.Capability = &c
		if err := r.authorize(&req); err == nil || err.Code != proto.ErrGrantInvalid {
			t.Fatalf("mismatch %d accepted", i)
		}
	}
	// A paused grant fails closed at the endpoint, and resuming restores the
	// same capability rather than issuing a new one.
	conv.Pause()
	waitGrant(t, r, cr.AccessID, proto.ConsentPaused)
	req := base
	req.Capability = &cap
	if err := r.authorize(&req); err == nil || err.Code != proto.ErrGrantInvalid {
		t.Fatal("paused grant accepted an operation")
	}
	conv.Resume()
	if resumed := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap; resumed.GrantID != cap.GrantID || resumed.Nonce != cap.Nonce {
		t.Fatal("resuming reissued the capability")
	}
	req = base
	req.Capability = &cap
	if err := r.authorize(&req); err != nil {
		t.Fatalf("resumed grant: %v", err)
	}

	if resp := r.endAccess(proto.EndAccessArgs{AccessID: cap.AccessID, GrantID: cap.GrantID, Nonce: cap.Nonce}); resp.Error != nil {
		t.Fatal(resp.Error)
	}
	req = base
	req.Capability = &cap
	if err := r.authorize(&req); err == nil {
		t.Fatal("terminated grant replay accepted")
	}
}

// The relay sets a grant's expiry by its own clock. On 2026-09-12 the laptop
// ran 3.3s behind the relay, so an hour-long grant forwarded the moment its
// unlock was approved ended a little more than an hour from now by the
// laptop's clock, and the endpoint refused it. Within the approval clock skew
// that is taken; beyond it, not.
func TestEndpointAllowsTheRelaysClockSkew(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ahead time.Duration // how far the relay's clock runs ahead of this one
		ok    bool
	}{
		{"a relay 3.3s ahead", 3300 * time.Millisecond, true},
		{"a relay just inside the skew", proto.ApprovalClockSkew - time.Second, true},
		{"a relay beyond the skew", proto.ApprovalClockSkew + time.Second, false},
	} {
		r := consentRunner(consentscript.New())
		cr := consentRequest()
		cr.Duration, cr.IdleTimeout = proto.MaxConsentDuration, 30*time.Minute
		cr.ExpiresAt = time.Now().UTC().Add(proto.MaxConsentDuration + tc.ahead)
		resp := r.consent(context.Background(), cr)
		switch {
		case tc.ok && resp.Error != nil:
			t.Errorf("%s: refused: %+v", tc.name, resp.Error)
		case !tc.ok && (resp.Error == nil || resp.Error.Code != proto.ErrBadRequest):
			t.Errorf("%s: answered %+v, want bad_request", tc.name, resp.Error)
		}
		r.cancelWork()
	}
}

func TestEndpointRejectsConsentThatWidensRequest(t *testing.T) {
	script := consentscript.New()
	r := consentRunner(script)
	cr := consentRequest()
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Widen("local-user", filepath.Dir(cr.Paths[0]))
	waitGrant(t, r, cr.AccessID, "") // the endpoint keeps no grant it cannot justify
}

// The endpoint, not the relay, is what stops an unattended machine from
// holding a request open forever.
func TestEndpointDeniesUndecidedRequestAtItsOwnDeadline(t *testing.T) {
	script := consentscript.New()
	r := consentRunner(script)
	cr := consentRequest()
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Waiting(proto.ReasonNoUser)
	waitGrant(t, r, cr.AccessID, "")
}

// Ending access needs only the access ID. The relay can record a termination
// before an approval that crossed it in flight reaches it, and so quote no
// capability; the endpoint must still let the grant go.
func TestEndpointEndsAGrantKnownOnlyByAccessID(t *testing.T) {
	script := consentscript.New()
	r := consentRunner(script)
	cr := consentRequest()
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Approve("local-user")
	cap := waitGrant(t, r, cr.AccessID, proto.ConsentApproved).cap
	if resp := r.endAccess(proto.EndAccessArgs{AccessID: cr.AccessID}); resp.Error != nil {
		t.Fatalf("end by access ID: %v", resp.Error)
	}
	waitGrant(t, r, cr.AccessID, "")
	req := proto.Request{Op: proto.OpReadFile, Caller: proto.Caller{Tech: "alice"}, Capability: &cap}
	if err := r.authorize(&req); err == nil {
		t.Fatal("an ended grant still authorised an operation")
	}
	if resp := r.endAccess(proto.EndAccessArgs{AccessID: cr.AccessID}); resp.Error == nil {
		t.Fatal("a grant was ended twice")
	}
}

// A decision is made once. A pause before any decision, a second approval of
// a live grant, or a resume of one that is not paused changes nothing: the
// grant keeps its capability and the relay is told nothing new.
func TestEndpointKeepsTheCapabilityOnARepeatedApproval(t *testing.T) {
	script := consentscript.New()
	r := consentRunner(script)
	cr := consentRequest()
	ack(t, r, cr)
	conv, err := script.Wait(context.Background(), cr.AccessID)
	if err != nil {
		t.Fatal(err)
	}
	conv.Pause() // nothing is granted yet, so there is nothing to pause
	conv.Approve("local-user")
	first := waitGrant(t, r, cr.AccessID, proto.ConsentApproved)
	if first.seq != 1 {
		t.Fatalf("seq %d after the first decision: the early pause was reported", first.seq)
	}
	conv.Resume() // an approval of a grant that is not paused
	conv.Pause()
	paused := waitGrant(t, r, cr.AccessID, proto.ConsentPaused)
	if paused.cap.GrantID != first.cap.GrantID || paused.cap.Nonce != first.cap.Nonce {
		t.Fatal("a repeated approval replaced the capability")
	}
	if paused.seq != first.seq+1 {
		t.Fatalf("seq %d after %d: the repeated approval was reported", paused.seq, first.seq)
	}
	conv.Pause() // pausing twice changes nothing
	conv.Resume()
	resumed := waitGrant(t, r, cr.AccessID, proto.ConsentApproved)
	if resumed.seq != paused.seq+1 || resumed.cap.GrantID != first.cap.GrantID {
		t.Fatalf("resume after a repeated pause: seq %d, grant %s", resumed.seq, resumed.cap.GrantID)
	}
}

func TestEndpointRefusesDuplicateAccessID(t *testing.T) {
	r := consentRunner(consentscript.New())
	cr := consentRequest()
	ack(t, r, cr)
	if resp := r.consent(context.Background(), cr); resp.Error == nil || resp.Error.Code != proto.ErrGrantInvalid {
		t.Fatalf("duplicate access request accepted: %+v", resp)
	}
}

func TestEndpointRefusesWhenNoConsentApplication(t *testing.T) {
	r := consentRunner(nil)
	if resp := r.consent(context.Background(), consentRequest()); resp.Error == nil || resp.Error.Code != proto.ErrConsentRequired {
		t.Fatalf("request accepted without a consent application: %+v", resp)
	}
}
