package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// grant puts an access request in the fixture's store in the given state.
func (f *fixture) consentGrant(state string, tweak ...func(*model.AccessRequest)) model.AccessRequest {
	decided := f.now.Add(-time.Minute)
	a := model.AccessRequest{ID: "acc_" + state, Client: "acme", Device: "dev_acme_srv01", Technician: "alice@msp",
		Session: "ses_alice", Purpose: "diagnose", State: state, RequestedScope: []string{cbsLog},
		RequestedOperations: []string{proto.OpReadFile}, EffectiveScope: []string{cbsLog},
		EffectiveOperations: []string{proto.OpReadFile}, RequestedAt: f.now.Add(-2 * time.Minute),
		ExpiresAt: f.now.Add(time.Hour), GrantID: "grt_one", Nonce: "nonce_one", DecidedAt: &decided, PolicyVersion: 1}
	for _, fn := range tweak {
		fn(&a)
	}
	f.dir.update(func(d *fakeDir) { d.access[a.ID] = a })
	return a
}

// A grant the endpoint user has paused, and one nobody has decided yet, are
// both refused before the call reaches the machine.
func TestGatewayRefusesPausedAndUndecidedGrants(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	paused := f.consentGrant(model.AccessPaused, func(a *model.AccessRequest) { a.Reason = proto.ReasonUIGone })
	pending := f.consentGrant(model.AccessAwaiting, func(a *model.AccessRequest) { a.GrantID, a.Nonce, a.DecidedAt = "", "", nil })
	before := len(f.acme.requests())
	for _, id := range []string{paused.ID, pending.ID} {
		text, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": cbsLog, "access_id": id})
		if !isErr || !strings.HasPrefix(text, proto.ErrGrantInvalid+":") {
			t.Fatalf("%s read = %q, error %v", id, text, isErr)
		}
	}
	if len(f.acme.requests()) != before {
		t.Fatal("a paused or undecided grant reached the agent")
	}
	if !strings.Contains(mustRead(t, f, paused.ID), model.AccessPaused) {
		t.Fatal("access_status did not report the pause")
	}
}

// The relay refuses a request nobody decided within the consent window, on
// its own, and a decision that arrives afterwards cannot revive it.
func TestGatewayEnforcesTheConsentWindow(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	overdue := f.now.Add(-time.Second)
	a := f.consentGrant(model.AccessAwaiting, func(a *model.AccessRequest) {
		a.ID, a.GrantID, a.Nonce, a.DecidedAt, a.ConsentDeadline = "acc_overdue", "", "", nil, &overdue
	})
	text, isErr := call(t, cs, ToolAccessStatus, map[string]any{"access_id": a.ID})
	if isErr {
		t.Fatalf("access_status: %s", text)
	}
	var got model.AccessRequest
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != model.AccessDenied || got.Reason != proto.ReasonTimeout {
		t.Fatalf("overdue request: %+v", got)
	}
	stored, err := f.dir.Access(context.Background(), a.ID)
	if err != nil || stored.State != model.AccessDenied {
		t.Fatalf("refusal was not durable: %+v, %v", stored, err)
	}
	if !slices.ContainsFunc(f.entries(t, "acme"), func(e audit.Entry) bool {
		return e.Kind == audit.KindConsent && e.Tool == "access."+model.AccessDenied && e.ErrorMessage == proto.ReasonTimeout
	}) {
		t.Fatal("the refusal was not audited")
	}
}

// Reducing access always works: a paused grant can still be ended.
func TestEndAccessWorksOnAPausedGrant(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.consentGrant(model.AccessPaused)
	text, isErr := call(t, cs, proto.OpEndAccess, map[string]any{"access_id": a.ID})
	// The fixture's agent does not implement end_access, so the gateway
	// reports the endpoint failure; the state must be terminated regardless,
	// which is what makes termination fail closed.
	stored, err := f.dir.Access(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != model.AccessTerminated {
		t.Fatalf("end_access on a paused grant = %q (%q, error %v)", stored.State, text, isErr)
	}
}

// A call in flight when the endpoint user pauses the grant still returns
// what the endpoint served, but the pause stands: activation moves the
// stored row, not the copy the call was admitted with.
func TestActivationNeverOverwritesAPauseRecordedMidCall(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.consentGrant(model.AccessApproved)
	f.acme.mu.Lock()
	f.acme.during = func(proto.Request) {
		f.dir.update(func(d *fakeDir) {
			cur, paused := d.access[a.ID], f.now
			cur.State, cur.PausedAt, cur.Reason = model.AccessPaused, &paused, proto.ReasonUser
			d.access[a.ID] = cur
		})
	}
	f.acme.mu.Unlock()
	text, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": cbsLog, "access_id": a.ID})
	if isErr || !strings.Contains(text, "disk full") {
		t.Fatalf("read the endpoint served = %q, error %v", text, isErr)
	}
	stored, err := f.dir.Access(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != model.AccessPaused {
		t.Fatalf("activation overwrote the pause: stored state %q", stored.State)
	}
	if slices.ContainsFunc(f.entries(t, "acme"), func(e audit.Entry) bool { return e.Tool == "access."+model.AccessActive }) {
		t.Fatal("a paused grant was recorded as active")
	}
}

// A deadline the relay enforces itself never overwrites a decision that
// landed after the request was read: the refusal is decided against the
// stored row.
func TestConsentDeadlineNeverOverwritesALaterDecision(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	overdue := f.now.Add(-time.Second)
	a := f.consentGrant(model.AccessAwaiting, func(a *model.AccessRequest) {
		a.ID, a.GrantID, a.Nonce, a.DecidedAt, a.ConsentDeadline = "acc_raced", "", "", nil, &overdue
	})
	f.dir.update(func(d *fakeDir) {
		d.txHook = func(access map[string]model.AccessRequest, id string) {
			cur, decided := access[id], f.now
			cur.State, cur.GrantID, cur.Nonce, cur.DecidedAt, cur.Approver = model.AccessApproved, "grt_one", "nonce_one", &decided, "local-user"
			access[id] = cur
		}
	})
	text, isErr := call(t, cs, ToolAccessStatus, map[string]any{"access_id": a.ID})
	if isErr {
		t.Fatalf("access_status: %s", text)
	}
	var got model.AccessRequest
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	stored, err := f.dir.Access(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != model.AccessApproved || stored.State != model.AccessApproved || stored.GrantID != "grt_one" {
		t.Fatalf("the deadline overwrote a decision that beat it: reported %q, stored %+v", got.State, stored)
	}
	if slices.ContainsFunc(f.entries(t, "acme"), func(e audit.Entry) bool { return e.Tool == "access."+model.AccessDenied }) {
		t.Fatal("a refusal was recorded for a request the endpoint approved in time")
	}
}

// end_access ends what is stored, not what was read: an approval that landed
// in between is ended too, and the endpoint is told which grant it was.
func TestEndAccessEndsTheStoredGrant(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.consentGrant(model.AccessAwaiting, func(a *model.AccessRequest) { a.GrantID, a.Nonce, a.DecidedAt = "", "", nil })
	f.dir.update(func(d *fakeDir) {
		d.txHook = func(access map[string]model.AccessRequest, id string) {
			cur, decided := access[id], f.now
			cur.State, cur.GrantID, cur.Nonce, cur.DecidedAt = model.AccessApproved, "grt_late", "nonce_late", &decided
			access[id] = cur
		}
	})
	call(t, cs, proto.OpEndAccess, map[string]any{"access_id": a.ID})
	stored, err := f.dir.Access(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != model.AccessTerminated || stored.TerminatedAt == nil || stored.GrantID != "grt_late" {
		t.Fatalf("end_access did not end the stored grant: %+v", stored)
	}
	var sent *proto.EndAccessArgs
	for _, r := range f.acme.requests() {
		if r.Op == proto.OpEndAccess {
			sent = &proto.EndAccessArgs{}
			if err := json.Unmarshal(r.Args, sent); err != nil {
				t.Fatal(err)
			}
		}
	}
	if sent == nil || sent.AccessID != a.ID || sent.GrantID != "grt_late" || sent.Nonce != "nonce_late" {
		t.Fatalf("the endpoint was told to end %+v", sent)
	}
}

func mustRead(t *testing.T, f *fixture, id string) string {
	t.Helper()
	cs := f.connect(t, bearerACME)
	text, isErr := call(t, cs, ToolAccessStatus, map[string]any{"access_id": id})
	if isErr {
		t.Fatalf("access_status: %s", text)
	}
	return text
}
