package model

import (
	"errors"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

var t0 = time.Date(2026, 9, 11, 21, 0, 0, 0, time.UTC)

func TestAccessWaitsForAnUnlockThenForTheEndpoint(t *testing.T) {
	for _, c := range []struct {
		cur, next string
		ok        bool
	}{
		{AccessRequested, AccessAwaitingUnlock, true},
		{AccessAwaitingUnlock, AccessAwaiting, true},
		{AccessRequested, AccessAwaiting, true},
		{AccessAwaitingUnlock, AccessApproved, false}, // the endpoint decides, after the unlock
		{AccessAwaiting, AccessAwaitingUnlock, false}, // never backwards
		{AccessAwaitingUnlock, AccessActive, false},
		{AccessAwaitingUnlock, AccessDenied, true},
		{AccessAwaitingUnlock, AccessExpired, true},
		{AccessAwaitingUnlock, AccessTerminated, true},
		{AccessDenied, AccessAwaitingUnlock, false},
	} {
		if got := AccessAdvance(c.cur, c.next); got != c.ok {
			t.Errorf("AccessAdvance(%s, %s) = %v, want %v", c.cur, c.next, got, c.ok)
		}
	}
	a := AccessRequest{State: AccessAwaitingUnlock, RequestedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	if err := a.Usable(t0); !errors.Is(err, ErrPending) {
		t.Fatalf("a request waiting for an unlock is usable: %v", err)
	}
	deadline := t0.Add(UnlockApprovalWindow)
	a.ConsentDeadline = &deadline
	if a.ConsentOverdue(t0) || !a.ConsentOverdue(deadline) {
		t.Fatal("a request waiting for an unlock ignores its deadline")
	}
}

func TestUnlockTransitionsFailClosed(t *testing.T) {
	for _, c := range []struct {
		cur, next string
		ok        bool
	}{
		{UnlockAwaiting, UnlockActive, true},
		{UnlockAwaiting, UnlockDenied, true},
		{UnlockAwaiting, UnlockExpired, true},
		{UnlockAwaiting, UnlockLocked, true},
		{UnlockActive, UnlockExpired, true},
		{UnlockActive, UnlockLocked, true},
		{UnlockActive, UnlockDenied, false}, // an approval cannot be taken back as a denial
		{UnlockActive, UnlockAwaiting, false},
		{UnlockLocked, UnlockActive, false},
		{UnlockExpired, UnlockActive, false},
		{UnlockDenied, UnlockActive, false},
		{UnlockActive, UnlockActive, false},
	} {
		if got := UnlockAdvance(c.cur, c.next); got != c.ok {
			t.Errorf("UnlockAdvance(%s, %s) = %v, want %v", c.cur, c.next, got, c.ok)
		}
	}
}

func TestUnlockLiveAndDue(t *testing.T) {
	expires := t0.Add(time.Hour)
	u := Unlock{State: UnlockAwaiting, Deadline: t0.Add(UnlockApprovalWindow), Duration: time.Hour, IdleTimeout: 15 * time.Minute}
	if err := u.Live(t0); !errors.Is(err, ErrPending) {
		t.Fatalf("awaiting unlock Live = %v", err)
	}
	if state, _ := u.Due(t0); state != "" {
		t.Fatalf("awaiting unlock due early: %s", state)
	}
	if state, reason := u.Due(u.Deadline); state != UnlockExpired || reason != ReasonUnanswered {
		t.Fatalf("unanswered unlock Due = %s, %s", state, reason)
	}

	u.State, u.DecidedAt, u.ExpiresAt = UnlockActive, &t0, &expires
	if err := u.Live(t0); err != nil {
		t.Fatalf("fresh unlock Live = %v", err)
	}
	if err := u.Live(t0.Add(15 * time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("an unlock nobody used for its idle timeout is live: %v", err)
	}
	if state, reason := u.Due(t0.Add(15 * time.Minute)); state != UnlockExpired || reason != ReasonIdle {
		t.Fatalf("idle unlock Due = %s, %s", state, reason)
	}
	used := t0.Add(50 * time.Minute)
	u.LastUsedAt = &used
	if err := u.Live(t0.Add(59 * time.Minute)); err != nil {
		t.Fatalf("recently used unlock Live = %v", err)
	}
	if err := u.Live(expires); !errors.Is(err, ErrExpired) {
		t.Fatalf("unlock is live at its expiry: %v", err)
	}
	if state, reason := u.Due(expires); state != UnlockExpired || reason != proto.ReasonExpired {
		t.Fatalf("expired unlock Due = %s, %s", state, reason)
	}
	u.State = UnlockLocked
	if err := u.Live(t0); !errors.Is(err, ErrRevoked) {
		t.Fatalf("locked unlock Live = %v", err)
	}
	if state, _ := u.Due(expires); state != "" {
		t.Fatalf("locked unlock due again: %s", state)
	}
}

func TestUnlockSignedApprovalReproducesWhatWasSigned(t *testing.T) {
	u := Unlock{ID: "unl_1", Technician: "tech", Client: "acme", Purpose: "ticket 7", Nonce: "n"}
	if _, err := u.SignedApproval(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unapproved unlock produced a signed approval: %v", err)
	}
	expires, decided := t0.Add(time.Hour), t0.Add(time.Second)
	u.ExpiresAt, u.DecidedAt, u.Credential = &expires, &decided, "cred"
	u.Assertion = []byte(`{"credential_id":"cred","signature":"AQ=="}`)
	a, err := u.SignedApproval()
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != proto.ApprovalUnlock || !a.Signed() || !a.ApprovedAt.Equal(decided) || !a.SameSigned(u.Approval()) {
		t.Fatalf("signed approval = %+v", a)
	}
	if a.Assertion == nil || a.Assertion.CredentialID != "cred" || len(a.Assertion.Signature) != 1 {
		t.Fatalf("assertion = %+v", a.Assertion)
	}
}

func TestChangeTransitionsAndDue(t *testing.T) {
	for _, c := range []struct {
		cur, next string
		ok        bool
	}{
		{ChangeAwaiting, ChangeApproved, true},
		{ChangeAwaiting, ChangeDenied, true},
		{ChangeAwaiting, ChangeExpired, true},
		{ChangeAwaiting, ChangeApplied, false}, // nothing is written before its approval
		{ChangeApproved, ChangeApplied, true},
		{ChangeApproved, ChangeRefused, true},
		{ChangeApproved, ChangeFailed, true},
		{ChangeApproved, ChangeDenied, false},
		{ChangeApplied, ChangeFailed, false},
		{ChangeDenied, ChangeApproved, false},
	} {
		if got := ChangeAdvance(c.cur, c.next); got != c.ok {
			t.Errorf("ChangeAdvance(%s, %s) = %v, want %v", c.cur, c.next, got, c.ok)
		}
	}
	c := ChangeApproval{State: ChangeAwaiting, ExpiresAt: t0}
	if state, reason := c.Due(t0); state != ChangeExpired || reason != ReasonUnanswered {
		t.Fatalf("unanswered change Due = %s, %s", state, reason)
	}
	c.State = ChangeApproved
	if state, _ := c.Due(t0); state != "" {
		t.Fatalf("an approved change within the skew is due: %s", state)
	}
	if state, reason := c.Due(t0.Add(proto.ApprovalClockSkew)); state != ChangeFailed || reason != proto.ReasonExpired {
		t.Fatalf("a lost release Due = %s, %s", state, reason)
	}
}

// A sign-in stored with a longer expiry, from before the TTL was shortened,
// still ends CompanionSessionTTL after it was made.
func TestCompanionSessionEndsAtTheTTL(t *testing.T) {
	made := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	s := CompanionSession{CreatedAt: made, ExpiresAt: made.Add(12 * time.Hour)}
	if err := s.Valid(made.Add(CompanionSessionTTL - time.Second)); err != nil {
		t.Fatalf("inside the TTL: %v", err)
	}
	if err := s.Valid(made.Add(CompanionSessionTTL)); !errors.Is(err, ErrExpired) {
		t.Fatalf("at the TTL: %v, want expired", err)
	}
	s.ExpiresAt = made.Add(time.Minute)
	if err := s.Valid(made.Add(time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("at its stored expiry: %v, want expired", err)
	}
}
