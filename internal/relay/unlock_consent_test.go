package relay

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// unlockConsent is the consent fixture with the technician's unlock of acme,
// approved and active.
type unlockConsent struct {
	*consentFixture
	unlock model.Unlock
	label  string // how an endpoint names the technician's approval
}

func newUnlockConsent(t *testing.T) *unlockConsent {
	t.Helper()
	f := newConsentFixture(t)
	now := time.Now().UTC()
	u := model.Unlock{ID: "unl_acme", Technician: f.access.Technician, Client: "acme", Session: "idp_" + f.access.Technician,
		Purpose: "ticket 42", State: model.UnlockAwaiting, Duration: time.Hour, IdleTimeout: model.DefaultUnlockIdle,
		RequestedAt: now, Deadline: now.Add(model.UnlockApprovalWindow)}
	if err := f.h.st.CreateUnlock(bg, u); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	u, err := f.h.st.UpdateUnlockTx(bg, u.ID, func(r *model.Unlock) error {
		r.State, r.Nonce, r.ExpiresAt, r.DecidedAt, r.Credential = model.UnlockActive, "n1", &expires, &now, "Y3JlZC1hbGljZS1wYXNza2V5"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := u.SignedApproval()
	if err != nil {
		t.Fatal(err)
	}
	return &unlockConsent{consentFixture: f, unlock: u, label: signed.ApproverLabel()}
}

// underUnlock stores a request made under the unlock, awaiting its endpoint.
func (f *unlockConsent) underUnlock(id string, endpointConsent bool) model.AccessRequest {
	f.h.t.Helper()
	f.h.storeAccess(id, "acme", f.device, f.access.Technician)
	a, err := f.h.st.UpdateAccessTx(bg, id, func(r *model.AccessRequest) error {
		r.Unlock, r.EndpointConsent = f.unlock.ID, endpointConsent
		return nil
	})
	if err != nil {
		f.h.t.Fatal(err)
	}
	return a
}

func (f *unlockConsent) row(id string) model.AccessRequest {
	f.h.t.Helper()
	a, err := f.h.st.Access(bg, id)
	if err != nil {
		f.h.t.Fatal(err)
	}
	return a
}

// unlockGrant is a well-formed approval of the whole of a, naming approver,
// as an endpoint sends it.
func unlockGrant(a model.AccessRequest, seq uint64, approver string) proto.ConsentEvent {
	c := &proto.Capability{GrantID: "grt_" + a.ID, AccessID: a.ID, Nonce: "nonce_" + a.ID, Client: a.Client, Device: a.Device,
		Technician: a.Technician, Operations: slices.Clone(a.RequestedOperations), Paths: slices.Clone(a.RequestedScope),
		IssuedAt: time.Now().UTC(), ExpiresAt: a.ExpiresAt, IdleTimeout: a.IdleTimeout, PolicyVersion: a.PolicyVersion,
		Unlock: a.Unlock, EndpointConsent: a.EndpointConsent}
	return proto.ConsentEvent{AccessID: a.ID, Client: a.Client, Device: a.Device, Technician: a.Technician,
		State: proto.ConsentApproved, Approver: approver, Operations: slices.Clone(c.Operations), Paths: slices.Clone(c.Paths),
		Capability: c, Seq: seq, Time: time.Now().UTC()}
}

// A grant on a request made under a technician unlock must name that unlock
// and agree about endpoint consent, and where the unlock alone approved it,
// name the unlock's signed approval as its approver. A resume keeps the same
// binding.
func TestRelayHoldsAnUnlockedGrantToItsUnlock(t *testing.T) {
	f := newUnlockConsent(t)
	a := f.underUnlock("acc_unlocked", false)
	cases := []struct {
		name, why string
		mutate    func(*proto.ConsentEvent)
	}{
		{"capability names no unlock", "another unlock", func(ev *proto.ConsentEvent) { ev.Capability.Unlock = "" }},
		{"capability names another unlock", "another unlock", func(ev *proto.ConsentEvent) { ev.Capability.Unlock = "unl_other" }},
		{"capability claims endpoint consent", "endpoint consent", func(ev *proto.ConsentEvent) { ev.Capability.EndpointConsent = true }},
		{"the person at the machine approved", "another approver", func(ev *proto.ConsentEvent) { ev.Approver = `ACME\sam` }},
		{"another passkey approved", "another approver", func(ev *proto.ConsentEvent) {
			ev.Approver = "technician " + a.Technician + " (passkey c29tZXRoaW5n)"
		}},
	}
	for i, c := range cases {
		ev := unlockGrant(a, uint64(i+1), f.label)
		c.mutate(&ev)
		f.publish(ev)
		refused := f.waitRefusals(i + 1)
		if r := refused[len(refused)-1]; !strings.Contains(r.ErrorMessage, c.why) || r.RequestID != a.ID {
			t.Errorf("%s: refused because %q, want a reason mentioning %q", c.name, r.ErrorMessage, c.why)
		}
		if got := f.row(a.ID); got.State != model.AccessAwaiting || got.GrantID != "" {
			t.Fatalf("%s moved the request: %+v", c.name, got)
		}
	}
	f.publish(unlockGrant(a, 100, f.label))
	eventually(t, "the unlocked grant to be approved", func() bool { return f.row(a.ID).State == model.AccessApproved })
	if got := f.row(a.ID); got.Approver != f.label || got.GrantID != "grt_"+a.ID || got.Unlock != f.unlock.ID {
		t.Fatalf("approved: %+v", got)
	}

	// Paused and resumed, the grant must come back with the same unlock.
	pause := proto.ConsentEvent{AccessID: a.ID, Client: "acme", Device: f.device, Technician: a.Technician,
		State: proto.ConsentPaused, Reason: proto.ReasonUIGone, Seq: 101, Time: time.Now().UTC()}
	f.publish(pause)
	eventually(t, "the grant to pause", func() bool { return f.row(a.ID).State == model.AccessPaused })
	resume := unlockGrant(a, 102, f.label)
	resume.Capability.Unlock = ""
	f.publish(resume)
	refused := f.waitRefusals(len(cases) + 1)
	if r := refused[len(refused)-1]; !strings.Contains(r.ErrorMessage, "resumed grant") {
		t.Fatalf("a resume without the unlock was refused because %q", r.ErrorMessage)
	}
	if got := f.row(a.ID); got.State != model.AccessPaused {
		t.Fatalf("a resume without the unlock was applied: %+v", got)
	}
}

// Once the technician's unlock has ended, an endpoint's approval of a request
// made under it is refused: nothing can be granted on authority that is gone.
func TestRelayRefusesAGrantUnderAnUnlockThatIsNotActive(t *testing.T) {
	f := newUnlockConsent(t)
	a := f.underUnlock("acc_locked", false)
	if _, err := f.h.st.UpdateUnlockTx(bg, f.unlock.ID, func(r *model.Unlock) error {
		ended := time.Now().UTC()
		r.State, r.Reason, r.EndedAt = model.UnlockLocked, model.ReasonLocked, &ended
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.publish(unlockGrant(a, 1, f.label))
	refused := f.waitRefusals(1)
	if r := refused[0]; !strings.Contains(r.ErrorMessage, "not active") {
		t.Fatalf("refused because %q", r.ErrorMessage)
	}
	if got := f.row(a.ID); got.State != model.AccessAwaiting || got.GrantID != "" {
		t.Fatalf("a grant landed under a locked unlock: %+v", got)
	}
}

// A request made without an unlock never holds a grant that claims one, or
// claims endpoint consent; its ordinary approval still lands.
func TestRelayRefusesAnUnlockClaimOnARequestMadeWithoutOne(t *testing.T) {
	f := newUnlockConsent(t)
	claimsUnlock := unlockGrant(f.access, 1, f.label)
	claimsUnlock.Capability.Unlock = f.unlock.ID
	f.publish(claimsUnlock)
	if r := f.waitRefusals(1)[0]; !strings.Contains(r.ErrorMessage, "not made under one") {
		t.Fatalf("an unlock claim was refused because %q", r.ErrorMessage)
	}
	claimsConsent := unlockGrant(f.access, 2, `ACME\sam`)
	claimsConsent.Capability.EndpointConsent = true
	f.publish(claimsConsent)
	if r := f.waitRefusals(2)[1]; !strings.Contains(r.ErrorMessage, "endpoint consent") {
		t.Fatalf("an endpoint-consent claim was refused because %q", r.ErrorMessage)
	}
	if got := f.state(); got.State != model.AccessAwaiting || got.GrantID != "" {
		t.Fatalf("a refused claim moved the request: %+v", got)
	}
	f.publish(f.approval(3, f.access.RequestedScope))
	if got := f.waitState(model.AccessApproved); got.Unlock != "" || got.Approver != `ACME\sam` {
		t.Fatalf("the ordinary approval: %+v", got)
	}
}

// Where the client's policy asks the person at the machine as well, the
// approver is theirs, and the grant still carries the unlock.
func TestRelayAcceptsTheMachinesApprovalUnderEndpointConsent(t *testing.T) {
	f := newUnlockConsent(t)
	a := f.underUnlock("acc_both", true)
	f.publish(unlockGrant(a, 1, `ACME\sam`))
	eventually(t, "the grant to be approved", func() bool { return f.row(a.ID).State == model.AccessApproved })
	if got := f.row(a.ID); got.Approver != `ACME\sam` || !got.EndpointConsent || got.Unlock != f.unlock.ID {
		t.Fatalf("approved: %+v", got)
	}
}
