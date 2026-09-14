package companion_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Approving rides the sign-in: the page posts an empty body, and the approval
// names the passkey the technician signed in with.
func TestApproveUnlock(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	h.advance(10 * time.Second)

	r := a.approve("unlocks", u.ID)
	h.must(r, http.StatusOK)
	var view struct {
		State   string `json:"state"`
		Passkey string `json:"passkey"`
	}
	if decodeJSON(t, r.body, &view); view.State != model.UnlockActive || view.Passkey != "idp|alice's laptop" {
		t.Fatalf("answer %s", r.body)
	}
	stored, err := h.st.Unlock(bg, u.ID)
	if err != nil || stored.Nonce == "" || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(h.clock().Add(time.Hour)) {
		t.Fatalf("approving left the unlock %+v, %v", stored, err)
	}
	calls := h.gate.Calls("ApproveUnlock")
	if len(calls) != 1 || calls[0].ID != u.ID {
		t.Fatalf("gate calls %+v", calls)
	}
	got := calls[0].Approval
	switch {
	case !got.SameSigned(stored.Approval()):
		t.Error("the approval does not sign the stored unlock")
	case got.Credential != a.key.CredentialID() || !got.Signed():
		t.Errorf("credential %q, signed %v", got.Credential, got.Signed())
	case got.Assertion != nil:
		t.Errorf("an approval on the sign-in carries an assertion: %+v", got.Assertion)
	case !got.ApprovedAt.Equal(h.clock()):
		t.Errorf("approved at %s, want %s", got.ApprovedAt, h.clock())
	}
}

func TestApproveUnlockRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	for _, tc := range []struct {
		name   string
		before func(model.Unlock)
		status int
	}{
		{"an unlock no longer awaiting", func(u model.Unlock) {
			h.must(h.post("/api/unlocks/"+u.ID+"/deny", a.cookie, nil), http.StatusOK)
		}, http.StatusConflict},
		{"an unlock past its deadline", func(model.Unlock) { h.advance(model.UnlockApprovalWindow) }, http.StatusGone},
	} {
		u := h.unlock(alice, "acme")
		tc.before(u)
		approvals := len(h.gate.Calls("ApproveUnlock"))
		if r := a.approve("unlocks", u.ID); r.status != tc.status {
			t.Errorf("%s: %d, want %d: %s", tc.name, r.status, tc.status, r.body)
		}
		if len(h.gate.Calls("ApproveUnlock")) != approvals {
			t.Errorf("%s: the gate was asked to approve", tc.name)
		}
	}
	// The sign-in is what approves, so one made with a passkey revoked since
	// approves nothing.
	spare := h.newTech(alice).enroll()
	if err := h.st.RevokePasskey(bg, spare.key.CredentialID(), h.clock()); err != nil {
		t.Fatal(err)
	}
	u := h.unlock(alice, "acme")
	if r := spare.approve("unlocks", u.ID); r.status != http.StatusUnauthorized {
		t.Fatalf("a revoked passkey's sign-in: %d", r.status)
	}
	if got, _ := h.st.Unlock(bg, u.ID); got.State != model.UnlockAwaiting || got.Nonce != "" {
		t.Fatalf("a revoked passkey's sign-in changed the unlock: %+v", got)
	}
}

func TestAnUnlockIsApprovedOnce(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	h.must(a.approve("unlocks", u.ID), http.StatusOK)
	if r := a.approve("unlocks", u.ID); r.status != http.StatusConflict {
		t.Fatalf("the same unlock approved again: %d", r.status)
	}
	if n := len(h.gate.Calls("ApproveUnlock")); n != 1 {
		t.Fatalf("the gate was asked %d times", n)
	}
}

func TestApproveChange(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	h.must(a.approve("unlocks", u.ID), http.StatusOK)
	c := h.change(alice, h.access(alice, u.ID))
	h.gate.setResult(`{"path":"C:\\ProgramData\\Vendor\\config.json","after_sha256":"` + afterHash + `","rollback_id":"rbk_1"}`)

	h.advance(20 * time.Second)
	r := a.approve("changes", c.ID)
	h.must(r, http.StatusOK)
	var view struct {
		State    string         `json:"state"`
		Hostname string         `json:"hostname"`
		Result   map[string]any `json:"result"`
		Plan     *struct {
			Path string `json:"path"`
		} `json:"plan"`
	}
	decodeJSON(t, r.body, &view)
	if view.State != model.ChangeApplied || view.Hostname != "SRV-ACME-01" || view.Result["rollback_id"] != "rbk_1" ||
		view.Plan == nil || view.Plan.Path != planPath {
		t.Fatalf("answer %s", r.body)
	}
	if got, _ := h.st.ChangeApproval(bg, c.ID); got.Nonce != c.Nonce || !got.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatal("approving changed what the change's approval signs")
	}
	calls := h.gate.Calls("ApproveChange")
	if len(calls) != 1 {
		t.Fatalf("gate calls %+v", calls)
	}
	got := calls[0].Approval
	if !got.SameSigned(c.Approval()) || got.Credential != a.key.CredentialID() || got.Assertion != nil ||
		!got.ApprovedAt.Equal(h.clock()) {
		t.Fatalf("approval %+v", got)
	}
}

func TestApproveChangeRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	h.must(a.approve("unlocks", u.ID), http.StatusOK)
	acc := h.access(alice, u.ID)
	for _, tc := range []struct {
		name   string
		before func(model.ChangeApproval)
		status int
	}{
		{"a change no longer awaiting", func(c model.ChangeApproval) {
			h.must(h.post("/api/changes/"+c.ID+"/deny", a.cookie, nil), http.StatusOK)
		}, http.StatusConflict},
		{"an expired change", func(model.ChangeApproval) { h.advance(model.ChangeApprovalWindow) }, http.StatusGone},
	} {
		c := h.change(alice, acc)
		tc.before(c)
		if r := a.approve("changes", c.ID); r.status != tc.status {
			t.Errorf("%s: %d, want %d: %s", tc.name, r.status, tc.status, r.body)
		}
	}
	if calls := h.gate.Calls("ApproveChange"); len(calls) != 0 {
		t.Fatalf("the gate was asked to release: %+v", calls)
	}
}

func TestOtherTechniciansCardsAreNotFound(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	h.newTech(bob).enroll()
	bu := h.unlock(bob, "acme")
	bc := h.change(bob, h.access(bob, bu.ID))
	before, _ := h.st.Unlock(bg, bu.ID)

	missing := h.post("/api/unlocks/unl_nope/deny", a.cookie, nil)
	if missing.status != http.StatusNotFound {
		t.Fatalf("a missing card: %d", missing.status)
	}
	for _, r := range []reply{
		h.post("/api/unlocks/"+bu.ID+"/approve", a.cookie, nil),
		h.post("/api/unlocks/"+bu.ID+"/deny", a.cookie, nil),
		h.post("/api/unlocks/"+bu.ID+"/lock", a.cookie, nil),
		h.get("/api/unlocks/"+bu.ID+"/receipt", a.cookie),
		h.post("/api/changes/"+bc.ID+"/approve", a.cookie, nil),
		h.post("/api/changes/"+bc.ID+"/deny", a.cookie, nil),
	} {
		if r.status != http.StatusNotFound || r.code() != proto.ErrNotFound || !bytes.Equal(r.body, missing.body) {
			t.Errorf("another technician's card: %d %s", r.status, r.body)
		}
	}
	if calls := h.gate.Calls(""); len(calls) != 0 {
		t.Fatalf("another technician's card reached the gate: %+v", calls)
	}
	if after, _ := h.st.Unlock(bg, bu.ID); after.Nonce != before.Nonce || after.ExpiresAt != nil {
		t.Fatal("alice's approve touched bob's unlock")
	}
	r := h.get("/api/state", a.cookie)
	if bytes.Contains(r.body, []byte(bu.ID)) || bytes.Contains(r.body, []byte(bc.ID)) {
		t.Fatal("alice's state shows bob's cards")
	}
}

func TestDenyAndLock(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	state := func(r reply) string {
		var v struct {
			State string `json:"state"`
		}
		decodeJSON(t, r.body, &v)
		return v.State
	}

	u := h.unlock(alice, "acme")
	r := h.post("/api/unlocks/"+u.ID+"/deny", a.cookie, nil)
	h.must(r, http.StatusOK)
	if s := state(r); s != model.UnlockDenied {
		t.Fatalf("deny answered %s", s)
	}
	if c := h.gate.Calls("DenyUnlock"); len(c) != 1 || c[0].ID != u.ID || c[0].Technician != alice || c[0].Credential != a.key.CredentialID() {
		t.Fatalf("DenyUnlock calls %+v", c)
	}

	u = h.unlock(alice, "acme")
	h.must(a.approve("unlocks", u.ID), http.StatusOK)
	r = h.send(http.MethodPost, "/api/unlocks/"+u.ID+"/lock", a.cookie, []byte{}) // an empty body is fine
	h.must(r, http.StatusOK)
	if s := state(r); s != model.UnlockLocked {
		t.Fatalf("lock answered %s", s)
	}
	if c := h.gate.Calls("Lock"); len(c) != 1 || c[0].ID != u.ID || c[0].Technician != alice || c[0].Reason != model.ReasonLocked {
		t.Fatalf("Lock calls %+v", c)
	}

	c := h.change(alice, h.access(alice, u.ID))
	r = h.post("/api/changes/"+c.ID+"/deny", a.cookie, nil)
	h.must(r, http.StatusOK)
	if s := state(r); s != model.ChangeDenied {
		t.Fatalf("change deny answered %s", s)
	}
	if calls := h.gate.Calls("DenyChange"); len(calls) != 1 || calls[0].ID != c.ID || calls[0].Credential != a.key.CredentialID() {
		t.Fatalf("DenyChange calls %+v", calls)
	}
}

func TestGateErrorsMapToStatuses(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	for _, tc := range []struct {
		err    error
		status int
	}{
		{fmt.Errorf("gateway: %w", model.ErrNotFound), http.StatusNotFound},
		{fmt.Errorf("gateway: %w", model.ErrConflict), http.StatusConflict},
		{fmt.Errorf("gateway: %w", model.ErrExpired), http.StatusGone},
		{fmt.Errorf("gateway: %w", model.ErrInvalid), http.StatusBadRequest},
		{fmt.Errorf("gateway: %w", model.ErrRevoked), http.StatusForbidden},
		{errors.New("gateway: the NATS connection dropped"), http.StatusInternalServerError},
	} {
		h.gate.setErr(tc.err)
		u := h.unlock(alice, "acme")
		r := h.post("/api/unlocks/"+u.ID+"/deny", a.cookie, nil)
		if r.status != tc.status {
			t.Errorf("%v: %d, want %d", tc.err, r.status, tc.status)
		}
		if tc.status == http.StatusInternalServerError && strings.Contains(string(r.body), "NATS") {
			t.Error("an internal error reached the page")
		}
	}
}
