package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Tests of how the two halves of technician approval fit together: unlocks
// and access requests (unlock.go, consent.go) and the change gate (gate.go).

// s6Advance moves the unlock fixture's clock on, keeping its machines online,
// as they keep reporting in while time passes.
func s6Advance(u *unlockFixture, d time.Duration) {
	u.now = u.now.Add(d)
	seen := u.now
	u.dir.update(func(dir *fakeDir) {
		for _, devs := range dir.devices {
			for i := range devs {
				if devs[i].RevokedAt == nil {
					devs[i].LastSeen = &seen
				}
			}
		}
	})
}

// Under technician approval every call on a machine runs under a grant the
// technician's unlock made. A client-bound session that calls without one is
// refused before anything reaches the machine, though it can still list the
// client's machines and ask for access.
func TestTechnicianApprovalRefusesCallsWithoutAGrant(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, bearerACME)
	before := len(u.acme.requests())
	for tool, args := range opArgs("SRV01") {
		text, isErr := call(t, cs, tool, args)
		if !isErr || !strings.HasPrefix(text, proto.ErrGrantInvalid+":") || !strings.Contains(text, "request_access") {
			t.Errorf("%s without an access grant = %q", tool, text)
		}
	}
	if n := len(u.acme.requests()) - before; n != 0 {
		t.Fatalf("%d calls without a grant reached the machine", n)
	}
	if text, isErr := call(t, cs, ToolListDevices, map[string]any{}); isErr {
		t.Fatalf("list_devices: %s", text)
	}
	if got := u.request(t, cs, map[string]any{"device": "SRV01", "purpose": "ticket 7"}); got.State != model.AccessAwaitingUnlock {
		t.Fatalf("request_access: %+v", got)
	}
}

// A request that waited for the technician gets its whole lifetime from when
// its endpoint first sees it, never beyond the unlock.
func TestAForwardedRequestStartsItsLifetimeWhenForwarded(t *testing.T) {
	u := newUnlockFixture(t)
	cs := u.connect(t, unlockBearer)
	waiting := u.request(t, cs, unlockAsk(map[string]any{"duration_minutes": 10}))
	if waiting.State != model.AccessAwaitingUnlock {
		t.Fatalf("request: %+v", waiting)
	}
	s6Advance(u, 8*time.Minute)
	u.approve(t, waiting.UnlockID)
	row := u.accessRow(t, waiting.ID)
	if !row.ExpiresAt.Equal(u.now.Add(10*time.Minute)) || row.IdleTimeout != 10*time.Minute {
		t.Fatalf("forwarded after waiting 8 minutes: expires %v (want %v), idle %v", row.ExpiresAt, u.now.Add(10*time.Minute), row.IdleTimeout)
	}
	if cr := unlockForward(t, u.acme, waiting.ID); cr.Duration != 10*time.Minute || !cr.ExpiresAt.Equal(row.ExpiresAt) {
		t.Fatalf("forwarded as duration %v, expires %v", cr.Duration, cr.ExpiresAt)
	}
}

// s6ActiveUnlock stores an unlock of acme that tech approved just now.
func s6ActiveUnlock(t *testing.T, f *gateFixture, tech, session string) model.Unlock {
	t.Helper()
	now := f.clock.now().UTC()
	expires := now.Add(time.Hour)
	u := model.Unlock{ID: model.NewID(model.PrefixUnlock), Technician: tech, Client: "acme", Session: session, Purpose: "ticket 42",
		State: model.UnlockActive, Duration: time.Hour, IdleTimeout: model.DefaultUnlockIdle, RequestedAt: now,
		Deadline: now.Add(model.UnlockApprovalWindow), Nonce: "nonce", ExpiresAt: &expires, DecidedAt: &now, LastUsedAt: &now,
		Credential: "cred-alice"}
	if err := f.st.CreateUnlock(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// s6UnlockedGrant stores a grant of tech's made under unlock unl.
func s6UnlockedGrant(t *testing.T, f *gateFixture, unl model.Unlock, ops ...string) model.AccessRequest {
	t.Helper()
	a := f.grant(t, unl.Technician, unl.Session, time.Hour, ops...)
	a.Unlock = unl.ID
	if err := f.st.UpdateAccess(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

// Submitting and approving a change reach no machine, but they are use of the
// unlock all the same: a change approved twenty minutes after the last call on
// the machine, well past the unlock's fifteen idle minutes, is still released.
func TestTheChangeGateKeepsTheUnlockFromIdling(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	unl := s6ActiveUnlock(t, f, "tech_alice", "idp_gate_alice")
	a := s6UnlockedGrant(t, f, unl, proto.OpPrepareFileChange, proto.OpApplyFileChange)
	planID, digest := f.prepare(t, cs, a, "retries=5\n")

	f.advance(10 * time.Minute)
	sub := f.apply(t, cs, a, planID, digest)
	stored, err := f.st.Unlock(context.Background(), unl.ID)
	if err != nil || stored.LastUsedAt == nil || !stored.LastUsedAt.Equal(f.clock.now().UTC()) {
		t.Fatalf("submitting a change did not count as use of the unlock: %+v, %v", stored.LastUsedAt, err)
	}

	f.advance(10 * time.Minute)
	if done := f.approve(t, sub.ApprovalID, "cred-alice"); done.State != model.ChangeApplied {
		t.Fatalf("a change approved in time under a live unlock: %s (%s %s)", done.State, done.ErrorCode, done.Reason)
	}
}

// A change still waiting for the technician under a grant that ends, by Lock
// or end_access, lapses at once: no release could run under that grant any
// more, so its card must not wait for an approval that could only be refused.
func TestEndingAGrantLapsesItsPendingChanges(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	unl := s6ActiveUnlock(t, f, "tech_alice", "idp_gate_alice")
	ops := []string{proto.OpPrepareFileChange, proto.OpApplyFileChange}

	locked := s6UnlockedGrant(t, f, unl, ops...)
	planID, digest := f.prepare(t, cs, locked, "retries=5\n")
	sub := f.apply(t, cs, locked, planID, digest)
	if _, err := f.g.Lock(context.Background(), unl.ID, "tech_alice", ""); err != nil {
		t.Fatal(err)
	}
	if got := f.row(t, sub.ApprovalID); got.State != model.ChangeExpired || !strings.Contains(got.Reason, "access grant ended") {
		t.Fatalf("a change under a locked unlock: %s (%s)", got.State, got.Reason)
	}
	if _, err := f.g.ApproveChange(context.Background(), sub.ApprovalID, f.sign(f.row(t, sub.ApprovalID), "cred-alice")); err == nil {
		t.Fatal("a lapsed change could still be approved")
	}

	ended := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, ops...)
	planID, digest = f.prepare(t, cs, ended, "retries=6\n")
	sub = f.apply(t, cs, ended, planID, digest)
	if text, isErr := call(t, cs, proto.OpEndAccess, map[string]any{"access_id": ended.ID}); isErr &&
		!strings.Contains(text, "endpoint revocation failed") {
		t.Fatalf("end_access: %s", text)
	}
	if got := f.row(t, sub.ApprovalID); got.State != model.ChangeExpired {
		t.Fatalf("a change under an ended grant: %s (%s)", got.State, got.Reason)
	}
}
