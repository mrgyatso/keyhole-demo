package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// A request for a client the technician has not unlocked reaches no machine:
// it waits on an unlock card in the companion, and a second request for the
// same client waits on the same card.
func TestUnlockRequestWaitsForTheTechnician(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, unlockBearer)
	first := u.request(t, cs, unlockAsk(nil))
	switch {
	case first.State != model.AccessAwaitingUnlock || first.UnlockID == "" || first.Unlock != first.UnlockID || first.AccessID != first.ID:
		t.Fatalf("first request: %+v", first)
	case first.Link != unlockCompanion+"/u/"+first.UnlockID || !strings.Contains(first.Next, "Keyhole companion"):
		t.Fatalf("the answer does not send the technician to the unlock card: link %q, next %q", first.Link, first.Next)
	}
	unl := u.unlockRow(t, first.UnlockID)
	switch {
	case unl.State != model.UnlockAwaiting || unl.Technician != unlockTech || unl.Client != "acme" || unl.Session != unlockSession:
		t.Fatalf("unlock: %+v", unl)
	case unl.Duration != model.MaxUnlockDuration || unl.IdleTimeout != model.DefaultUnlockIdle || unl.Purpose != "ticket 42":
		t.Fatalf("unlock lifetime or purpose: %+v", unl)
	case !unl.Deadline.Equal(u.now.Add(model.UnlockApprovalWindow)):
		t.Fatalf("unlock deadline %v", unl.Deadline)
	}
	row := u.accessRow(t, first.ID)
	var roots []string
	for _, r := range u.dir.clients["acme"].Policy.Allow["windows"] {
		roots = append(roots, r.Path)
	}
	switch {
	case row.ConsentDeadline == nil || !row.ConsentDeadline.Equal(unl.Deadline):
		t.Errorf("the request's deadline is not the unlock's: %v", row.ConsentDeadline)
	case !slices.Equal(row.RequestedOperations, readOperations):
		t.Errorf("default operations %v, want every read", row.RequestedOperations)
	case !slices.Equal(row.RequestedScope, roots):
		t.Errorf("default paths %v, want the client's allow-rule roots %v", row.RequestedScope, roots)
	// The grant idles at the endpoint only after the unlock's idle timeout plus
	// a whole approval window (grantIdle).
	case !row.ExpiresAt.Equal(u.now.Add(time.Hour)) || row.IdleTimeout != model.DefaultUnlockIdle+model.ChangeApprovalWindow || row.EndpointConsent:
		t.Errorf("lifetime: %+v", row)
	}
	// A request still waiting is no grant.
	text, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": cbsLog, "access_id": first.ID})
	if !isErr || !strings.HasPrefix(text, proto.ErrGrantInvalid+":") || !strings.Contains(text, "waiting for approval") {
		t.Fatalf("read under a waiting request = %q", text)
	}

	second := u.request(t, cs, unlockAsk(map[string]any{"device": "web01", "duration_minutes": 10}))
	if second.State != model.AccessAwaitingUnlock || second.UnlockID != first.UnlockID {
		t.Fatalf("a second request for the same client made its own unlock: %+v", second)
	}
	if web := u.accessRow(t, second.ID); !slices.Equal(web.RequestedScope, []string{"/var/log", "/etc", "/var/opt/mssql/log"}) ||
		!web.ExpiresAt.Equal(u.now.Add(10*time.Minute)) || web.IdleTimeout != 10*time.Minute {
		t.Errorf("second request: %+v", web)
	}
	if open, err := u.st.UnlocksOpen(context.Background()); err != nil || len(open) != 1 {
		t.Fatalf("open unlocks %d, %v; want the one card", len(open), err)
	}
	if n := len(unlockForwards(t, u.acme)); n != 0 {
		t.Fatalf("%d requests reached the machine before the technician unlocked the client", n)
	}
	if n := len(u.unlockEntries(t, "acme", "unlock."+model.UnlockAwaiting)); n != 1 {
		t.Errorf("audit has %d unlock requests, want 1", n)
	}
	if n := len(u.unlockEntries(t, "acme", "access."+model.AccessAwaitingUnlock)); n != 2 {
		t.Errorf("audit has %d requests awaiting the unlock, want 2", n)
	}
}

// Approving the unlock forwards every request waiting for it, each with the
// technician's signed approval, capped at the unlock's expiry and with an
// idle timeout that fits what is left of it.
func TestApproveUnlockForwardsTheWaitingRequests(t *testing.T) {
	u := newUnlockFixture(t)
	unlockEndpoint(u.fixture, u.acme, 0)
	cs := u.connect(t, unlockBearer)
	a := u.request(t, cs, unlockAsk(nil))
	b := u.request(t, cs, unlockAsk(map[string]any{"device": "web01", "duration_minutes": 10}))
	// b has waited six of its ten minutes. Forwarded with its ten-minute idle
	// timeout, the endpoint would refuse it: the idle timeout must shrink.
	u.dir.update(func(d *fakeDir) {
		r := d.access[b.ID]
		r.ExpiresAt = u.now.Add(4 * time.Minute)
		d.access[b.ID] = r
	})

	// The technician opened the card a minute ago, so the unlock ends a
	// minute before a would: a must be capped at the unlock's expiry.
	began := u.begin(t, a.UnlockID, u.now.Add(-time.Minute))
	unl, err := u.g.ApproveUnlock(context.Background(), a.UnlockID, unlockSigned(began, unlockCred, u.now))
	if err != nil {
		t.Fatal(err)
	}
	if unl.State != model.UnlockActive || unl.Credential != unlockCred || unl.DecidedAt == nil || !unl.DecidedAt.Equal(u.now) || len(unl.Assertion) == 0 {
		t.Fatalf("approved unlock: %+v", unl)
	}
	signed, err := unl.SignedApproval()
	if err != nil {
		t.Fatal(err)
	}
	forwards := unlockForwards(t, u.acme)
	if len(forwards) != 2 {
		t.Fatalf("%d requests forwarded, want 2", len(forwards))
	}
	for _, cr := range forwards {
		stored := u.accessRow(t, cr.AccessID)
		switch {
		case cr.Approval == nil || !cr.Approval.SameSigned(signed) || cr.Approval.Credential != unlockCred ||
			!cr.Approval.ApprovedAt.Equal(u.now) || cr.Approval.Assertion == nil:
			t.Errorf("%s was forwarded without the technician's signed unlock: %+v", cr.AccessID, cr.Approval)
		case cr.Approval.Kind != proto.ApprovalUnlock || cr.Approval.Client != cr.Client || cr.Approval.Technician != cr.Technician || cr.EndpointConsent:
			t.Errorf("%s: the unlock does not bind the request: %+v", cr.AccessID, cr)
		case cr.ExpiresAt.After(cr.Approval.ExpiresAt) || cr.Duration <= 0 || cr.IdleTimeout > cr.Duration || cr.Duration > proto.MaxConsentDuration:
			t.Errorf("%s would outlive its unlock or be refused by the endpoint: expires %v (unlock %v), duration %v, idle %v",
				cr.AccessID, cr.ExpiresAt, cr.Approval.ExpiresAt, cr.Duration, cr.IdleTimeout)
		case stored.State != model.AccessApproved || stored.Approver != signed.ApproverLabel() || stored.IdleTimeout != cr.IdleTimeout:
			t.Errorf("%s after forwarding: %+v", cr.AccessID, stored)
		case stored.ConsentDeadline == nil || !stored.ConsentDeadline.Equal(u.now.Add(proto.ConsentTimeout)):
			t.Errorf("%s: the consent window did not restart: %v", cr.AccessID, stored.ConsentDeadline)
		}
	}
	if fb := unlockForward(t, u.acme, b.ID); fb.IdleTimeout != 4*time.Minute || fb.Duration != 4*time.Minute {
		t.Errorf("the shortened request was forwarded with duration %v and idle timeout %v", fb.Duration, fb.IdleTimeout)
	}
	if fa := u.accessRow(t, a.ID); !fa.ExpiresAt.Equal(*unl.ExpiresAt) || !unl.ExpiresAt.Equal(u.now.Add(59*time.Minute)) {
		t.Errorf("a request that would outlive its unlock was not capped at it: %v, unlock %v", fa.ExpiresAt, *unl.ExpiresAt)
	}

	entries := u.unlockEntries(t, "acme", "unlock."+model.UnlockActive)
	if len(entries) != 1 {
		t.Fatalf("audit has %d unlock approvals, want 1", len(entries))
	}
	var args unlockAuditArgs
	if e := entries[0]; e.RequestID != unl.ID || e.Tech != unlockTech || e.SessionID != unlockSession || e.Result != audit.ResultOK ||
		json.Unmarshal(e.Args, &args) != nil || args.Source != "technician" || args.Credential != unlockCred || args.Purpose != "ticket 42" ||
		args.ExpiresAt == nil {
		t.Fatalf("unlock approval audited as %+v (%s)", e, e.Args)
	}
	if n := len(u.unlockEntries(t, "acme", "access."+model.AccessAwaiting)); n != 2 {
		t.Errorf("audit has %d forwarded requests, want 2", n)
	}
	if v, err := u.store.Verify(context.Background(), "acme"); err != nil || !v.OK {
		t.Fatalf("audit chain: %+v %v", v, err)
	}
}

// Under an active unlock a request is approved within the wait and every read
// tool works with its access ID; each call is recorded against the unlock.
func TestUnlockedClientGrantsAtOnceAndRecordsEveryCall(t *testing.T) {
	u := newUnlockFixture(t)
	// The endpoint's decision lands after the acknowledgement, as it does
	// when the relay records the endpoint's event.
	unlockEndpoint(u.fixture, u.acme, 150*time.Millisecond)
	cs := u.connect(t, unlockBearer)
	first := u.request(t, cs, unlockAsk(nil))
	unl := u.approve(t, first.UnlockID)
	signed, _ := unl.SignedApproval()

	got := u.request(t, cs, unlockAsk(map[string]any{"duration_minutes": 5, "paths": []string{`C:\Windows\Logs`}}))
	switch {
	case got.State != model.AccessApproved || got.Unlock != unl.ID || !strings.Contains(got.Next, "Approved"):
		t.Fatalf("a request under an active unlock was not approved within the wait: %+v", got)
	case !got.ExpiresAt.Equal(u.now.Add(5*time.Minute)) || got.IdleTimeout != 5*time.Minute:
		t.Fatalf("grant lifetime %v, idle %v", got.ExpiresAt, got.IdleTimeout)
	}
	if cr := unlockForward(t, u.acme, got.ID); cr.Approval == nil || !cr.Approval.SameSigned(signed) || cr.Duration != 5*time.Minute ||
		!slices.Equal(cr.Paths, []string{`C:\Windows\Logs`}) || !slices.Equal(cr.Operations, readOperations) {
		t.Fatalf("forwarded as %+v", cr)
	}

	before := len(u.acme.requests())
	for tool, args := range opArgs("SRV01") {
		args["access_id"] = got.ID
		if text, isErr := call(t, cs, tool, args); isErr {
			t.Fatalf("%s under the unlocked grant: %s", tool, text)
		}
	}
	for _, r := range u.acme.requests()[before:] {
		if r.Capability == nil || r.Capability.Unlock != unl.ID || r.Capability.AccessID != got.ID || r.Capability.EndpointConsent {
			t.Errorf("%s carried capability %+v", r.Op, r.Capability)
		}
	}
	used := u.unlockRow(t, unl.ID)
	if used.Calls != 6 || !slices.Equal(used.Devices, []string{"dev_acme_srv01"}) || used.LastUsedAt == nil {
		t.Fatalf("unlock after six calls: calls %d, devices %v, last used %v", used.Calls, used.Devices, used.LastUsedAt)
	}
	acts, err := u.st.UnlockActivity(context.Background(), unl.ID, 0)
	if err != nil || len(acts) != 6 {
		t.Fatalf("activity %+v, %v", acts, err)
	}
	var ops []string
	for _, a := range acts {
		ops = append(ops, a.Op)
		if a.Result != audit.ResultOK || a.Device != "dev_acme_srv01" || a.Path == "" {
			t.Errorf("activity %+v", a)
		}
	}
	slices.Sort(ops)
	if !slices.Equal(ops, []string{proto.OpGrep, proto.OpHashFile, proto.OpListDir, proto.OpReadFile, proto.OpSearchFiles, proto.OpStat}) {
		t.Errorf("activity ops %v", ops)
	}

	// A call the endpoint refuses reached the machine, so it is recorded too.
	missing := `C:\Windows\Logs\missing.log`
	if _, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": missing, "access_id": got.ID}); !isErr {
		t.Fatal("the fake endpoint served a file it does not have")
	}
	acts, _ = u.st.UnlockActivity(context.Background(), unl.ID, 1)
	if len(acts) != 1 || acts[0].Path != missing || acts[0].Result != audit.ResultDenied || acts[0].ErrorCode != proto.ErrNotAllowed {
		t.Fatalf("a refused call was recorded as %+v", acts)
	}
}

// Where the client's policy asks the person at the machine too, the unlock is
// still attached, and request_access answers at once instead of waiting for a
// person.
func TestEndpointConsentPolicyStillAsksTheMachine(t *testing.T) {
	u := newUnlockFixture(t)
	unlockEndpoint(u.fixture, u.acme, 0)
	u.dir.update(func(d *fakeDir) {
		c := d.clients["acme"]
		c.Policy.EndpointConsent = true
		d.clients["acme"] = c
	})
	cs := u.connect(t, unlockBearer)
	first := u.request(t, cs, unlockAsk(nil))
	unl := u.approve(t, first.UnlockID)
	if fa := u.accessRow(t, first.ID); fa.State != model.AccessAwaiting || !fa.EndpointConsent {
		t.Fatalf("the waiting request was forwarded as %+v", fa)
	}

	began := time.Now()
	got := u.request(t, cs, unlockAsk(nil))
	if took := time.Since(began); took > decisionWait/2 {
		t.Errorf("request_access waited %v for a decision the person at the machine makes", took)
	}
	if got.State != model.AccessAwaiting || !got.EndpointConsent || !strings.Contains(got.Next, "person at the machine") {
		t.Fatalf("answer: %+v", got)
	}
	if cr := unlockForward(t, u.acme, got.ID); !cr.EndpointConsent || cr.Approval == nil || cr.Approval.ID != unl.ID {
		t.Fatalf("forwarded as %+v", cr)
	}
}

// The gate activates an unlock only on an approval of exactly that row, by a
// live passkey of its own technician, within the ceremony window, before its
// deadline, and only while it awaits approval. Nothing is forwarded otherwise.
func TestApproveUnlockRefusesAnythingButItsOwnApproval(t *testing.T) {
	u := newUnlockFixture(t)
	unlockEndpoint(u.fixture, u.acme, 0)
	ctx := context.Background()
	type attempt struct {
		name  string
		setup func(t *testing.T, id string) proto.TechnicianApproval
		want  error
	}
	signedNow := func(t *testing.T, id string) proto.TechnicianApproval {
		return unlockSigned(u.begin(t, id, u.now), unlockCred, u.now)
	}
	for _, c := range []attempt{
		{"another technician", func(t *testing.T, id string) proto.TechnicianApproval {
			a := unlockSigned(u.begin(t, id, u.now), unlockOtherCred, u.now)
			a.Technician = unlockOtherTech
			return a
		}, model.ErrNotFound},
		{"a nonce rotated by a later begin", func(t *testing.T, id string) proto.TechnicianApproval {
			a := signedNow(t, id)
			u.begin(t, id, u.now)
			return a
		}, model.ErrInvalid},
		{"another expiry", func(t *testing.T, id string) proto.TechnicianApproval {
			a := signedNow(t, id)
			a.ExpiresAt = a.ExpiresAt.Add(time.Hour)
			return a
		}, model.ErrInvalid},
		{"an unsigned approval", func(t *testing.T, id string) proto.TechnicianApproval {
			a := signedNow(t, id)
			a.Credential, a.ApprovedAt = "", time.Time{}
			return a
		}, model.ErrInvalid},
		{"a revoked passkey", func(t *testing.T, id string) proto.TechnicianApproval {
			return unlockSigned(u.begin(t, id, u.now), unlockOldCred, u.now)
		}, model.ErrRevoked},
		{"another technician's passkey", func(t *testing.T, id string) proto.TechnicianApproval {
			return unlockSigned(u.begin(t, id, u.now), unlockOtherCred, u.now)
		}, model.ErrInvalid},
		{"a stale ceremony", func(t *testing.T, id string) proto.TechnicianApproval {
			began := u.now.Add(-model.CeremonyTimeout - time.Second)
			return unlockSigned(u.begin(t, id, began), unlockCred, u.now)
		}, model.ErrExpired},
		{"no ceremony", func(t *testing.T, id string) proto.TechnicianApproval {
			return unlockSigned(u.unlockRow(t, id), unlockCred, u.now)
		}, model.ErrInvalid},
		{"an unlock already denied", func(t *testing.T, id string) proto.TechnicianApproval {
			a := signedNow(t, id)
			if _, err := u.g.DenyUnlock(ctx, id, unlockTech, unlockCred); err != nil {
				t.Fatal(err)
			}
			return a
		}, model.ErrConflict},
	} {
		t.Run(c.name, func(t *testing.T) {
			unl := u.pendingUnlock(t, "acme", u.now)
			waiting := u.waitingRow(t, unl, "dev_acme_srv01")
			_, err := u.g.ApproveUnlock(ctx, unl.ID, c.setup(t, unl.ID))
			if !errors.Is(err, c.want) {
				t.Fatalf("ApproveUnlock = %v, want %v", err, c.want)
			}
			if got := u.unlockRow(t, unl.ID); got.State == model.UnlockActive || got.Credential == unlockOtherCred {
				t.Fatalf("the unlock was activated: %+v", got)
			}
			if got := u.accessRow(t, waiting.ID); got.State == model.AccessAwaiting || got.State == model.AccessApproved {
				t.Fatalf("the waiting request was forwarded: %+v", got)
			}
		})
	}
	// An unlock nobody answered by its deadline cannot be approved late.
	late := u.pendingUnlock(t, "acme", u.now.Add(-model.UnlockApprovalWindow))
	if _, err := u.g.ApproveUnlock(ctx, late.ID, signedNow(t, late.ID)); !errors.Is(err, model.ErrExpired) {
		t.Fatalf("an unlock past its deadline: %v", err)
	}
	if n := len(unlockForwards(t, u.acme)); n != 0 {
		t.Fatalf("%d requests reached the machine on a refused approval", n)
	}
	// And the real approval works.
	unl := u.pendingUnlock(t, "acme", u.now)
	if got, err := u.g.ApproveUnlock(ctx, unl.ID, signedNow(t, unl.ID)); err != nil || got.State != model.UnlockActive {
		t.Fatalf("the valid approval = %+v, %v", got, err)
	}
}

// A technician has one client unlocked at a time: approving another locks the
// first and ends the grants made under it, at the relay and at the endpoint.
func TestUnlockingAnotherClientLocksTheFirst(t *testing.T) {
	u := newUnlockFixture(t)
	unlockEndpoint(u.fixture, u.acme, 0)
	unlockEndpoint(u.fixture, u.globex, 0)
	u.dir.update(func(d *fakeDir) { d.acl[unlockTech]["globex"] = true })
	cs := u.connect(t, unlockBearer)
	acme := u.request(t, cs, unlockAsk(nil))
	acmeUnlock := u.approve(t, acme.UnlockID)
	grant := u.accessRow(t, acme.ID)
	if grant.State != model.AccessApproved {
		t.Fatalf("acme grant: %+v", grant)
	}
	if text, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": cbsLog, "access_id": acme.ID}); isErr {
		t.Fatalf("read under acme's unlock: %s", text)
	}

	globex := u.request(t, cs, unlockAsk(map[string]any{"client": "globex", "device": "GLOBEX-DC01"}))
	if globex.State != model.AccessAwaitingUnlock || globex.UnlockID == acme.UnlockID {
		t.Fatalf("globex request: %+v", globex)
	}
	u.approve(t, globex.UnlockID)

	ended := u.unlockRow(t, acmeUnlock.ID)
	if ended.State != model.UnlockLocked || ended.Reason != model.ReasonSwitched || ended.EndedAt == nil {
		t.Fatalf("acme's unlock after unlocking globex: %+v", ended)
	}
	if g := u.accessRow(t, acme.ID); g.State != model.AccessTerminated || g.Reason != model.ReasonSwitched || g.TerminatedAt == nil {
		t.Fatalf("acme's grant after unlocking globex: %+v", g)
	}
	if !slices.Contains(unlockRevocations(t, u.acme), proto.EndAccessArgs{AccessID: acme.ID, GrantID: grant.GrantID, Nonce: grant.Nonce}) {
		t.Fatalf("acme's endpoint was not told to revoke the grant: %+v", unlockRevocations(t, u.acme))
	}
	before := len(u.acme.requests())
	text, isErr := call(t, cs, proto.OpReadFile, map[string]any{"device": "SRV01", "path": cbsLog, "access_id": acme.ID})
	if !isErr || !strings.HasPrefix(text, proto.ErrGrantInvalid+":") || len(u.acme.requests()) != before {
		t.Fatalf("read under the locked client = %q; reached the machine: %t", text, len(u.acme.requests()) != before)
	}
	if gx := u.accessRow(t, globex.ID); gx.State != model.AccessApproved {
		t.Fatalf("globex request: %+v", gx)
	}
	if es := u.unlockEntries(t, "acme", "unlock."+model.UnlockLocked); len(es) != 1 || es[0].ErrorMessage != model.ReasonSwitched ||
		es[0].RequestID != acmeUnlock.ID {
		t.Fatalf("acme's lock audited as %+v", es)
	}
	if es := u.unlockEntries(t, "acme", "access."+model.AccessTerminated); len(es) != 1 || es[0].RequestID != acme.ID ||
		es[0].Tech != unlockTech || es[0].SessionID != unlockSession {
		t.Fatalf("acme's grant ending audited as %+v", es)
	}
}

// Denying an unlock denies every request waiting for it, and the unlock can
// be neither denied nor approved again.
func TestDenyUnlockDeniesTheRequestsWaitingForIt(t *testing.T) {
	u := newUnlockFixture(t)
	ctx := context.Background()
	cs := u.connect(t, unlockBearer)
	a := u.request(t, cs, unlockAsk(nil))
	if _, err := u.g.DenyUnlock(ctx, a.UnlockID, unlockOtherTech, unlockOtherCred); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another technician denied the unlock: %v", err)
	}
	got, err := u.g.DenyUnlock(ctx, a.UnlockID, unlockTech, unlockCred)
	if err != nil || got.State != model.UnlockDenied || got.Reason != model.ReasonDenied || got.EndedAt == nil || got.Credential != unlockCred {
		t.Fatalf("DenyUnlock = %+v, %v", got, err)
	}
	if row := u.accessRow(t, a.ID); row.State != model.AccessDenied || row.Reason != model.ReasonDenied || row.DecidedAt == nil {
		t.Fatalf("the waiting request: %+v", row)
	}
	if _, err := u.g.DenyUnlock(ctx, a.UnlockID, unlockTech, unlockCred); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("denied twice: %v", err)
	}
	row := u.begin(t, a.UnlockID, u.now)
	if _, err := u.g.ApproveUnlock(ctx, a.UnlockID, unlockSigned(row, unlockCred, u.now)); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("a denied unlock was approved: %v", err)
	}
	if es := u.unlockEntries(t, "acme", "unlock."+model.UnlockDenied); len(es) != 1 || !strings.Contains(string(es[0].Args), unlockCred) {
		t.Fatalf("denial audited as %+v", es)
	}
	text, isErr := call(t, cs, ToolAccessStatus, map[string]any{"access_id": a.ID})
	if isErr || !strings.Contains(text, `"state":"denied"`) || !strings.Contains(text, "request_access again") {
		t.Fatalf("access_status after the denial = %q", text)
	}
	if again := u.request(t, cs, unlockAsk(nil)); again.UnlockID == a.UnlockID || again.State != model.AccessAwaitingUnlock {
		t.Fatalf("a request after the denial: %+v", again)
	}
	if n := len(unlockForwards(t, u.acme)); n != 0 {
		t.Fatalf("%d requests reached the machine", n)
	}
}

// Lock ends one unlock and its grants; LockAll, which is sign-out, ends every
// unlock of the technician, pending or active.
func TestLockAndLockAllEndTheUnlockAndItsGrants(t *testing.T) {
	u := newUnlockFixture(t)
	ctx := context.Background()
	unlockEndpoint(u.fixture, u.acme, 0)
	u.dir.update(func(d *fakeDir) { d.acl[unlockTech]["globex"] = true })
	cs := u.connect(t, unlockBearer)
	a := u.request(t, cs, unlockAsk(nil))
	unl := u.approve(t, a.UnlockID)
	grant := u.accessRow(t, a.ID)

	if _, err := u.g.Lock(ctx, unl.ID, unlockOtherTech, ""); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another technician locked the unlock: %v", err)
	}
	locked, err := u.g.Lock(ctx, unl.ID, unlockTech, "")
	if err != nil || locked.State != model.UnlockLocked || locked.Reason != model.ReasonLocked || locked.EndedAt == nil {
		t.Fatalf("Lock = %+v, %v", locked, err)
	}
	if g := u.accessRow(t, a.ID); g.State != model.AccessTerminated || g.Reason != model.ReasonLocked {
		t.Fatalf("grant after Lock: %+v", g)
	}
	if !slices.Contains(unlockRevocations(t, u.acme), proto.EndAccessArgs{AccessID: a.ID, GrantID: grant.GrantID, Nonce: grant.Nonce}) {
		t.Fatal("Lock did not revoke the grant at the endpoint")
	}
	if _, err := u.g.Lock(ctx, unl.ID, unlockTech, ""); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("locked twice: %v", err)
	}

	// Sign-out: one active unlock with a grant, one still pending.
	b := u.request(t, cs, unlockAsk(nil))
	active := u.approve(t, b.UnlockID)
	c := u.request(t, cs, unlockAsk(map[string]any{"client": "globex", "device": "GLOBEX-DC01"}))
	if err := u.g.LockAll(ctx, unlockTech, model.ReasonSignedOut); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{active.ID, c.UnlockID} {
		if got := u.unlockRow(t, id); got.State != model.UnlockLocked || got.Reason != model.ReasonSignedOut || got.EndedAt == nil {
			t.Errorf("unlock %s after sign-out: %+v", id, got)
		}
	}
	if g := u.accessRow(t, b.ID); g.State != model.AccessTerminated || g.Reason != model.ReasonSignedOut {
		t.Errorf("grant after sign-out: %+v", g)
	}
	if w := u.accessRow(t, c.ID); w.State != model.AccessDenied || w.Reason != model.ReasonSignedOut {
		t.Errorf("waiting request after sign-out: %+v", w)
	}
	if open, _ := u.st.UnlocksOpen(ctx); len(open) != 0 {
		t.Fatalf("unlocks left open after sign-out: %+v", open)
	}
}

// The reconcile loop expires an unlock nobody answered, one left idle and one
// past its lifetime, and ends what each authorised. A live one stays.
func TestReconcileExpiresUnansweredIdleAndOverdueUnlocks(t *testing.T) {
	u := newUnlockFixture(t)
	ctx := context.Background()
	unlockEndpoint(u.fixture, u.acme, 0)
	cs := u.connect(t, unlockBearer)
	a := u.request(t, cs, unlockAsk(nil))
	idle := u.approve(t, a.UnlockID)
	grant := u.accessRow(t, a.ID)
	idle = u.setUnlock(t, idle.ID, func(r *model.Unlock) {
		last := u.now.Add(-model.DefaultUnlockIdle)
		r.LastUsedAt = &last
	})
	stale := u.pendingUnlock(t, "globex", u.now.Add(-model.UnlockApprovalWindow))
	waiting := u.waitingRow(t, stale, "dev_globex_dc01")

	u.g.reconcileUnlocks(ctx)
	if got := u.unlockRow(t, stale.ID); got.State != model.UnlockExpired || got.Reason != model.ReasonUnanswered || got.EndedAt == nil {
		t.Errorf("unanswered unlock: %+v", got)
	}
	if w := u.accessRow(t, waiting.ID); w.State != model.AccessDenied || w.Reason != model.ReasonUnanswered {
		t.Errorf("request waiting for the unanswered unlock: %+v", w)
	}
	if got := u.unlockRow(t, idle.ID); got.State != model.UnlockExpired || got.Reason != model.ReasonIdle || got.EndedAt == nil {
		t.Errorf("idle unlock: %+v", got)
	}
	if g := u.accessRow(t, a.ID); g.State != model.AccessTerminated || g.Reason != model.ReasonIdle {
		t.Errorf("grant of the idle unlock: %+v", g)
	}
	if !slices.Contains(unlockRevocations(t, u.acme), proto.EndAccessArgs{AccessID: a.ID, GrantID: grant.GrantID, Nonce: grant.Nonce}) {
		t.Error("the idle unlock's grant was not revoked at the endpoint")
	}

	b := u.request(t, cs, unlockAsk(nil))
	overdue := u.approve(t, b.UnlockID)
	live := u.pendingUnlock(t, "globex", u.now)
	u.setUnlock(t, overdue.ID, func(r *model.Unlock) {
		over := u.now.Add(-time.Second)
		r.ExpiresAt = &over
	})
	u.g.reconcileUnlocks(ctx)
	if got := u.unlockRow(t, overdue.ID); got.State != model.UnlockExpired || got.Reason != proto.ReasonExpired {
		t.Errorf("unlock past its lifetime: %+v", got)
	}
	if g := u.accessRow(t, b.ID); g.State != model.AccessTerminated || g.Reason != proto.ReasonExpired {
		t.Errorf("grant of the overdue unlock: %+v", g)
	}
	if got := u.unlockRow(t, live.ID); got.State != model.UnlockAwaiting {
		t.Errorf("reconcile ended an unlock with time left: %+v", got)
	}
	if n := len(u.unlockEntries(t, "acme", "unlock."+model.UnlockExpired)); n != 2 {
		t.Errorf("audit has %d acme unlock expiries, want 2", n)
	}
}

// A call under a grant whose unlock has ended is refused at the relay before
// it reaches the machine, even before the reconcile loop has ended the grant,
// and a refusal that never reached the machine is not recorded as a call.
func TestCallsUnderAnEndedUnlockNeverReachTheMachine(t *testing.T) {
	for name, end := range map[string]func(r *model.Unlock, now time.Time){
		"locked": func(r *model.Unlock, now time.Time) {
			r.State, r.Reason, r.EndedAt = model.UnlockLocked, model.ReasonLocked, &now
		},
		"idle": func(r *model.Unlock, now time.Time) {
			last := now.Add(-model.DefaultUnlockIdle)
			r.LastUsedAt = &last
		},
		"past its lifetime": func(r *model.Unlock, now time.Time) { r.ExpiresAt = &now },
	} {
		t.Run(name, func(t *testing.T) {
			u := newUnlockFixture(t)
			unlockEndpoint(u.fixture, u.acme, 0)
			cs := u.connect(t, unlockBearer)
			a := u.request(t, cs, unlockAsk(nil))
			unl := u.approve(t, a.UnlockID)
			u.setUnlock(t, unl.ID, func(r *model.Unlock) { end(r, u.now) })
			if g := u.accessRow(t, a.ID); g.State != model.AccessApproved {
				t.Fatalf("the grant itself must still look usable for this test: %+v", g)
			}
			before := len(u.acme.requests())
			for tool, args := range opArgs("SRV01") {
				args["access_id"] = a.ID
				text, isErr := call(t, cs, tool, args)
				if !isErr || !strings.HasPrefix(text, proto.ErrGrantInvalid+":") || !strings.Contains(text, "unlock of this client has ended") {
					t.Errorf("%s under an ended unlock = %q", tool, text)
				}
				if e := u.lastEntry(t, "acme"); e.Tool != tool || e.Result != audit.ResultDenied {
					t.Errorf("%s refusal audited as %+v", tool, e)
				}
			}
			if n := len(u.acme.requests()) - before; n != 0 {
				t.Fatalf("%d calls reached the machine under an ended unlock", n)
			}
			if got := u.unlockRow(t, unl.ID); got.Calls != 0 {
				t.Fatalf("relay refusals were recorded as %d calls", got.Calls)
			}
		})
	}
}

// Every requested path must lie inside, or contain, a location the client's
// policy allows on that machine; anything else is refused before the
// technician is asked for anything.
func TestRequestAccessRefusesPathsOutsideThePolicy(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, unlockBearer)
	for _, bad := range []map[string]any{
		{"paths": []string{`C:\Users\alice\Documents`}},
		{"paths": []string{`C:\Windows\Logs`, `C:\Windows\System32\config`}},
		{"paths": []string{`C:\ProgramData\Vendor`}}, // beside the C:\ProgramData\*\Logs rule, not inside it
		{"paths": []string{"/var/log"}},              // another OS's syntax
		{"device": "web01", "paths": []string{"/home/alice"}},
	} {
		text, isErr := call(t, cs, proto.OpRequestAccess, unlockAsk(bad))
		if !isErr || !strings.HasPrefix(text, proto.ErrNotAllowed+":") {
			t.Errorf("paths %v = %q, error %t", bad["paths"], text, isErr)
		}
		if want := `C:\Windows\Logs`; bad["device"] == "web01" {
			if !strings.Contains(text, "/var/log") {
				t.Errorf("the refusal does not list the allowed locations: %q", text)
			}
		} else if !strings.Contains(text, want) {
			t.Errorf("the refusal does not list the allowed locations: %q", text)
		}
	}
	if open, _ := u.st.UnlocksOpen(context.Background()); len(open) != 0 {
		t.Fatalf("a refused request asked the technician to unlock the client: %+v", open)
	}
	if n := len(u.dir.access); n != 0 {
		t.Fatalf("a refused request was stored: %d rows", n)
	}
	for _, good := range []map[string]any{
		{"paths": []string{`C:\Windows`}},                  // contains a rule
		{"paths": []string{`C:\Windows\Logs\CBS`}},         // inside a rule
		{"paths": []string{`C:\ProgramData\Vendor\Logs`}},  // inside a glob rule
		{"paths": []string{`c:\windows\logs`}},             // Windows folds case
		{"device": "web01", "paths": []string{"/var"}},     // contains /var/log
		{"device": "web01", "paths": []string{"/etc/ssl"}}, // inside /etc
	} {
		if got := u.request(t, cs, unlockAsk(good)); got.State != model.AccessAwaitingUnlock {
			t.Errorf("paths %v: %+v", good["paths"], got)
		}
	}
}

// A request that can no longer be granted when its unlock is approved is
// denied with why instead of being forwarded, or when its endpoint does not
// take it.
func TestForwardDeniesRequestsThatCannotBeGranted(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, unlockBearer)
	offline := u.request(t, cs, unlockAsk(map[string]any{"device": "OLD01"}))
	refused := u.request(t, cs, unlockAsk(nil))
	changed := u.request(t, cs, unlockAsk(map[string]any{"device": "web01"}))
	u.dir.update(func(d *fakeDir) {
		c := d.clients["acme"]
		c.Policy.Version = 2
		d.clients["acme"] = c
	})
	// The policy change is what refuses changed; put its version back for
	// the others by giving them the new one.
	for _, id := range []string{offline.ID, refused.ID} {
		u.dir.update(func(d *fakeDir) {
			r := d.access[id]
			r.PolicyVersion = 2
			d.access[id] = r
		})
	}
	u.acme.mu.Lock()
	u.acme.tamper = true // the endpoint's acknowledgement fails its integrity check
	u.acme.mu.Unlock()
	u.approve(t, offline.UnlockID)

	for id, why := range map[string]string{
		offline.ID: "has not been heard from",
		refused.ID: "integrity check failed",
		changed.ID: "policy changed",
	} {
		got := u.accessRow(t, id)
		if got.State != model.AccessDenied || !strings.Contains(got.Reason, why) {
			t.Errorf("%s: %+v, want denied because %q", id, got, why)
		}
	}
	if n := len(u.unlockEntries(t, "acme", "access."+model.AccessDenied)); n != 3 {
		t.Errorf("audit has %d denials, want 3", n)
	}
}

// A legacy client-bound session takes the same flow, as its session's
// technician, and its instructions describe it.
func TestClientBoundSessionsUseTheUnlockFlow(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, bearerACME)
	got := u.request(t, cs, map[string]any{"device": "SRV01", "purpose": "ticket 7"})
	if got.State != model.AccessAwaitingUnlock {
		t.Fatalf("client-bound request: %+v", got)
	}
	if unl := u.unlockRow(t, got.UnlockID); unl.Technician != "alice@msp" || unl.Session != "ses_alice" || unl.Client != "acme" {
		t.Fatalf("client-bound unlock: %+v", unl)
	}
	ins := cs.InitializeResult().Instructions
	for _, want := range []string{"Keyhole companion", "awaiting_unlock", "awaiting_approval", "untrusted"} {
		if !strings.Contains(ins, want) {
			t.Errorf("client-bound instructions lack %q:\n%s", want, ins)
		}
	}
}

// Under technician approval the model is told how the technician approves,
// is told it never can, and has no tool that approves anything.
func TestTechnicianApprovalIsDescribedAndNoToolApproves(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, unlockBearer)
	ins := cs.InitializeResult().Instructions
	for _, want := range []string{"list_clients", "Keyhole companion", "awaiting_unlock", "access_id", "dry run",
		"awaiting_approval", "change_status", "rollback_file_change", "you never can", "Nothing you can call approves", "untrusted"} {
		if !strings.Contains(ins, want) {
			t.Errorf("instructions lack %q:\n%s", want, ins)
		}
	}
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if strings.Contains(tool.Name, "approve") || strings.Contains(tool.Name, "unlock") || strings.Contains(tool.Name, "grant") {
			t.Errorf("tool %s looks like it approves", tool.Name)
		}
		schema, _ := json.Marshal(tool.InputSchema)
		switch tool.Name {
		case proto.OpRequestAccess:
			if !strings.Contains(tool.Description, "awaiting_unlock") || !strings.Contains(string(schema), `"required":["device","purpose"]`) {
				t.Errorf("request_access: %s\n%s", tool.Description, schema)
			}
		case ToolAccessStatus:
			if !strings.Contains(tool.Description, "awaiting_unlock") {
				t.Errorf("access_status does not list awaiting_unlock: %s", tool.Description)
			}
		case proto.OpListDir, proto.OpStat, proto.OpReadFile, proto.OpSearchFiles, proto.OpGrep, proto.OpHashFile:
			if !strings.Contains(string(schema), `"access_id"`) {
				t.Errorf("%s takes no access_id: %s", tool.Name, schema)
			}
		}
	}
}

// Without a companion the Slice 3 flow is untouched: the person at the
// machine is asked, nothing carries an unlock, and the answer is the bare
// request.
func TestWithoutACompanionAccessStaysWithTheMachine(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	if ins := cs.InitializeResult().Instructions; strings.Contains(ins, "companion") || !strings.Contains(ins, "person at the machine") {
		t.Fatalf("legacy instructions:\n%s", ins)
	}
	// Paths stay required here, by the tool's schema as before.
	text, isErr := call(t, cs, proto.OpRequestAccess, map[string]any{"device": "SRV01", "purpose": "p", "duration_minutes": 5})
	if !isErr || !strings.Contains(text, "paths") {
		t.Fatalf("a legacy request without paths = %q", text)
	}
	text, isErr = call(t, cs, proto.OpRequestAccess, map[string]any{"device": "SRV01", "purpose": "p", "duration_minutes": 5, "paths": []string{cbsLog}})
	if isErr || strings.Contains(text, `"access_id"`) || !strings.Contains(text, `"state":"awaiting_consent"`) {
		t.Fatalf("legacy request_access = %q", text)
	}
	for _, cr := range unlockForwards(t, f.acme) {
		if cr.Approval != nil || cr.EndpointConsent {
			t.Fatalf("a legacy request carried an unlock: %+v", cr)
		}
	}
	// The read tools take an access ID here too, and a grant is checked.
	decided := f.now.Add(-time.Minute)
	f.dir.update(func(d *fakeDir) {
		d.access["acc_legacy"] = model.AccessRequest{ID: "acc_legacy", Client: "acme", Device: "dev_acme_srv01", Technician: "alice@msp",
			Session: "ses_alice", State: model.AccessApproved, EffectiveScope: []string{`C:\Windows\Logs`},
			EffectiveOperations: slices.Clone(readOperations), ExpiresAt: f.now.Add(time.Hour), GrantID: "grt_legacy",
			Nonce: "nonce_legacy", DecidedAt: &decided, PolicyVersion: 1}
	})
	before := len(f.acme.requests())
	if text, isErr := call(t, cs, proto.OpListDir, map[string]any{"device": "SRV01", "path": `C:\Windows\Logs`, "access_id": "acc_legacy"}); isErr {
		t.Fatalf("list_dir with a legacy grant: %s", text)
	}
	if reqs := f.acme.requests()[before:]; len(reqs) != 1 || reqs[0].Capability == nil || reqs[0].Capability.GrantID != "grt_legacy" {
		t.Fatalf("list_dir did not carry the grant: %+v", reqs)
	}
}
