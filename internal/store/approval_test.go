package store_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

// approvalFixture is two clients, one enrolled device in acme, and one access
// request on it, which is what unlocks and change approvals hang off.
func approvalFixture(t *testing.T) (*store.Store, model.AccessRequest, time.Time) {
	t.Helper()
	st, _ := openStore(t)
	addClient(t, st, "acme")
	addClient(t, st, "globex")
	now := time.Now().UTC()
	enr, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: addToken(t, st, "acme", nil),
		Device: newDevice("U-APPROVAL", "m-approval"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: "acme", Device: enr.Device.ID,
		Technician: "tech_alice", Session: "idp_s", Purpose: "p", State: model.AccessAwaitingUnlock, RequestedAt: now,
		ExpiresAt: now.Add(time.Hour), PolicyVersion: 1, Unlock: "unl_one", EndpointConsent: true}
	if err := st.CreateAccess(ctx, a); err != nil {
		t.Fatal(err)
	}
	return st, a, now
}

func newUnlock(t *testing.T, st *store.Store, client string, now time.Time) model.Unlock {
	t.Helper()
	u := model.Unlock{ID: model.NewID(model.PrefixUnlock), Technician: "tech_alice", Client: client, Session: "idp_s",
		Purpose: "ticket 1", State: model.UnlockAwaiting, Duration: time.Hour, IdleTimeout: model.DefaultUnlockIdle,
		RequestedAt: now, Deadline: now.Add(model.UnlockApprovalWindow)}
	if err := st.CreateUnlock(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAccessCarriesItsUnlock(t *testing.T) {
	st, a, _ := approvalFixture(t)
	got, err := st.Access(ctx, a.ID)
	if err != nil || got.Unlock != "unl_one" || !got.EndpointConsent || got.State != model.AccessAwaitingUnlock {
		t.Fatalf("Access = %+v, %v", got, err)
	}
	got.Unlock, got.EndpointConsent = "unl_two", false
	if err := st.UpdateAccess(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Access(ctx, a.ID); again.Unlock != "unl_two" || again.EndpointConsent {
		t.Fatalf("update lost the unlock binding: %+v", again)
	}
	if list, err := st.AccessForUnlock(ctx, "unl_two"); err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("AccessForUnlock = %+v, %v", list, err)
	}
	if list, _ := st.AccessForUnlock(ctx, "unl_one"); len(list) != 0 {
		t.Fatalf("the old unlock still lists the request: %+v", list)
	}
	if _, err := st.AccessForUnlock(ctx, ""); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("an empty unlock ID lists every legacy request: %v", err)
	}
}

func TestPasskeyEnrollmentIsOneUse(t *testing.T) {
	st, _ := openStore(t)
	now := time.Now().UTC()
	link := func() (model.PasskeyLink, string) {
		secret := model.NewSecret(model.SecretPasskeyLink)
		l := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: "tech_alice",
			Hash: model.HashSecret(secret), CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}
		if err := st.CreatePasskeyLink(ctx, l); err != nil {
			t.Fatal(err)
		}
		return l, secret
	}
	l, secret := link()
	if _, err := st.PasskeyLinkByToken(ctx, "khp_wrong", now); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown secret: %v", err)
	}
	if _, err := st.PasskeyLinkByToken(ctx, secret, now.Add(model.PasskeyLinkTTL)); !errors.Is(err, model.ErrExpired) {
		t.Fatalf("expired link: %v", err)
	}
	if got, err := st.PasskeyLinkByToken(ctx, secret, now); err != nil || got.ID != l.ID || got.Technician != "tech_alice" {
		t.Fatalf("PasskeyLinkByToken = %+v, %v", got, err)
	}

	pk := model.Passkey{CredentialID: "cred-1", Technician: "tech_alice", PublicKey: []byte{1, 2, 3}, Algorithm: -7, Name: "Touch ID"}
	other := pk
	other.Technician = "tech_bob"
	if err := st.UsePasskeyLink(ctx, l.ID, other, now); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("a link enrolled another technician's passkey: %v", err)
	}
	if err := st.UsePasskeyLink(ctx, l.ID, pk, now); err != nil {
		t.Fatal(err)
	}
	if err := st.UsePasskeyLink(ctx, l.ID, pk, now); !errors.Is(err, model.ErrExhausted) {
		t.Fatalf("a used link enrolled again: %v", err)
	}
	if _, err := st.PasskeyLinkByToken(ctx, secret, now); !errors.Is(err, model.ErrExhausted) {
		t.Fatalf("a used link still resolves: %v", err)
	}
	l2, secret2 := link()
	if err := st.UsePasskeyLink(ctx, l2.ID, pk, now); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("the same credential enrolled twice: %v", err)
	}
	if _, err := st.PasskeyLinkByToken(ctx, secret2, now); err != nil {
		t.Fatalf("a refused enrollment used the link up: %v", err)
	}

	got, err := st.Passkey(ctx, "cred-1")
	if err != nil || got.Technician != "tech_alice" || !slices.Equal(got.PublicKey, pk.PublicKey) || got.Algorithm != -7 ||
		got.Name != "Touch ID" || !got.CreatedAt.Equal(now) || got.Live() != nil {
		t.Fatalf("Passkey = %+v, %v", got, err)
	}
	if err := st.TouchPasskey(ctx, "cred-1", 7, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchPasskey(ctx, "cred-nope", 1, now); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("touch unknown passkey: %v", err)
	}
	revokedAt := now.Add(2 * time.Minute)
	if err := st.RevokePasskey(ctx, "cred-1", revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokePasskey(ctx, "cred-1", revokedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = st.Passkey(ctx, "cred-1")
	if got.SignCount != 7 || got.LastUsedAt == nil || !got.RevokedAt.Equal(revokedAt) || !errors.Is(got.Live(), model.ErrRevoked) {
		t.Fatalf("after touch and revoke: %+v", got)
	}
	if list, _ := st.PasskeysForTechnician(ctx, "tech_alice"); len(list) != 1 {
		t.Fatalf("PasskeysForTechnician = %+v", list)
	}
	if list, _ := st.PasskeysForTechnician(ctx, "tech_bob"); len(list) != 0 {
		t.Fatalf("another technician sees the passkey: %+v", list)
	}
}

func TestCompanionSignOutRevokesEverySession(t *testing.T) {
	st, _ := openStore(t)
	now := time.Now().UTC()
	secret := model.NewSecret(model.SecretCompanion)
	cs := model.CompanionSession{ID: model.NewID(model.PrefixCompanion), Technician: "tech_alice", Credential: "cred-1",
		Hash: model.HashSecret(secret), CreatedAt: now, ExpiresAt: now.Add(model.CompanionSessionTTL)}
	if err := st.CreateCompanionSession(ctx, cs); err != nil {
		t.Fatal(err)
	}
	got, err := st.CompanionSessionByToken(ctx, secret)
	if err != nil || got.ID != cs.ID || got.Valid(now) != nil {
		t.Fatalf("CompanionSessionByToken = %+v, %v", got, err)
	}
	if _, err := st.CompanionSessionByToken(ctx, "khc_wrong"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("unknown sign-in: %v", err)
	}
	if err := st.RevokeCompanionSessions(ctx, "tech_alice", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.CompanionSessionByToken(ctx, secret); !errors.Is(got.Valid(now), model.ErrRevoked) {
		t.Fatalf("sign-out left the session valid: %+v", got)
	}
}

func TestUnlockLifecycleLocksTheOtherClient(t *testing.T) {
	st, _, now := approvalFixture(t)
	acme := newUnlock(t, st, "acme", now)
	got, err := st.Unlock(ctx, acme.ID)
	if err != nil || got.State != model.UnlockAwaiting || got.Duration != time.Hour || !got.Deadline.Equal(acme.Deadline) ||
		got.Devices == nil || len(got.Devices) != 0 {
		t.Fatalf("Unlock = %+v, %v", got, err)
	}

	// A passkey ceremony begins: the nonce and the expiry are offered.
	offered := now.Add(time.Hour)
	if _, err := st.UpdateUnlockTx(ctx, acme.ID, func(u *model.Unlock) error {
		u.Nonce, u.ExpiresAt = "n1", &offered
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err = st.UpdateUnlockTx(ctx, acme.ID, func(u *model.Unlock) error {
		u.Nonce = "n2"
		return model.ErrConflict
	})
	if !errors.Is(err, model.ErrConflict) || got.Nonce != "n1" || !got.ExpiresAt.Equal(offered) {
		t.Fatalf("a refused update = %+v, %v", got, err)
	}
	if found, err := st.UnlockFor(ctx, "tech_alice", "acme", model.UnlockAwaiting); err != nil || found.ID != acme.ID {
		t.Fatalf("UnlockFor awaiting = %+v, %v", found, err)
	}
	if _, err := st.UnlockFor(ctx, "tech_alice", "acme", model.UnlockActive); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("UnlockFor active before approval: %v", err)
	}

	activate := func(id string, at time.Time) (model.Unlock, []model.Unlock) {
		t.Helper()
		u, locked, err := st.ActivateUnlockTx(ctx, id, func(u *model.Unlock) error {
			if !model.UnlockAdvance(u.State, model.UnlockActive) {
				return model.ErrConflict
			}
			u.State, u.DecidedAt, u.Credential = model.UnlockActive, &at, "cred-1"
			u.Assertion = []byte(`{"credential_id":"cred-1"}`)
			if u.ExpiresAt == nil {
				e := at.Add(u.Duration)
				u.ExpiresAt = &e
			}
			return nil
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		return u, locked
	}
	if a, locked := activate(acme.ID, now); a.State != model.UnlockActive || len(locked) != 0 {
		t.Fatalf("first activation = %+v, locked %+v", a, locked)
	}
	globex := newUnlock(t, st, "globex", now)
	g, locked := activate(globex.ID, now.Add(time.Minute))
	if len(locked) != 1 || locked[0].ID != acme.ID || locked[0].State != model.UnlockLocked ||
		locked[0].Reason != model.ReasonSwitched || locked[0].EndedAt == nil {
		t.Fatalf("unlocking globex locked %+v", locked)
	}
	if a, _ := st.Unlock(ctx, acme.ID); a.State != model.UnlockLocked {
		t.Fatalf("acme is still %s after globex was unlocked", a.State)
	}
	signed, err := g.SignedApproval()
	if err != nil || signed.Credential != "cred-1" || signed.Assertion == nil || !signed.SameSigned(g.Approval()) {
		t.Fatalf("SignedApproval = %+v, %v", signed, err)
	}

	pending := newUnlock(t, st, "acme", now)
	if _, _, err := st.ActivateUnlockTx(ctx, pending.ID, func(*model.Unlock) error { return nil }, now); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("an activation that left the unlock awaiting: %v", err)
	}
	open, err := st.UnlocksOpen(ctx)
	if err != nil || len(open) != 2 || slices.ContainsFunc(open, func(u model.Unlock) bool { return u.ID == acme.ID }) {
		t.Fatalf("UnlocksOpen = %+v, %v", open, err)
	}
	if recent, _ := st.Unlocks(ctx, "tech_alice", now.Add(time.Hour)); len(recent) != 2 {
		t.Fatalf("Unlocks since later lists %d, want the 2 open ones", len(recent))
	}
	if all, _ := st.Unlocks(ctx, "tech_alice", now.Add(-time.Minute)); len(all) != 3 {
		t.Fatalf("Unlocks since earlier lists %d, want 3", len(all))
	}
}

func TestRecordUnlockUse(t *testing.T) {
	st, _, now := approvalFixture(t)
	u := newUnlock(t, st, "acme", now)
	for i, dev := range []string{"dev_a", "dev_a", "dev_b"} {
		if err := st.RecordUnlockUse(ctx, u.ID, model.UnlockActivity{Time: now.Add(time.Duration(i) * time.Second),
			Op: proto.OpReadFile, Device: dev, Path: `C:\Logs\a.log`, Result: "ok", Bytes: 10}); err != nil {
			t.Fatal(err)
		}
	}
	// A call that finished earlier does not move the last use back.
	if err := st.RecordUnlockUse(ctx, u.ID, model.UnlockActivity{Time: now, Op: proto.OpHashFile, Device: "dev_a",
		Result: "denied", ErrorCode: proto.ErrNotAllowed}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Unlock(ctx, u.ID)
	if got.Calls != 4 || !slices.Equal(got.Devices, []string{"dev_a", "dev_b"}) || !got.LastUsedAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("after four calls: calls %d, devices %v, last used %v", got.Calls, got.Devices, got.LastUsedAt)
	}
	acts, err := st.UnlockActivity(ctx, u.ID, 2)
	if err != nil || len(acts) != 2 || acts[0].Op != proto.OpHashFile || acts[0].ErrorCode != proto.ErrNotAllowed ||
		acts[1].Device != "dev_b" || acts[1].Path != `C:\Logs\a.log` {
		t.Fatalf("UnlockActivity = %+v, %v", acts, err)
	}
	if err := st.RecordUnlockUse(ctx, u.ID, model.UnlockActivity{Op: proto.OpReadFile}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("incomplete activity: %v", err)
	}
	if err := st.RecordUnlockUse(ctx, "unl_nope", model.UnlockActivity{Time: now, Op: proto.OpReadFile, Device: "d",
		Result: "ok"}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("activity for an unknown unlock: %v", err)
	}
}

func TestChangeApprovalLifecycle(t *testing.T) {
	st, a, now := approvalFixture(t)
	plan := model.ChangePlanRecord{PlanID: "plan_1", AccessID: a.ID, Client: "acme", Device: a.Device, Technician: a.Technician,
		Digest: "d1", Plan: json.RawMessage(`{"plan_id":"plan_1","diff":"-a\n+b"}`), PreparedAt: now, ExpiresAt: now.Add(proto.ChangePlanTTL)}
	if err := st.CreateChangePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateChangePlan(ctx, plan); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("the same plan stored twice: %v", err)
	}
	bad := plan
	bad.PlanID, bad.Plan = "plan_2", json.RawMessage("not json")
	if err := st.CreateChangePlan(ctx, bad); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("a plan that is not JSON: %v", err)
	}
	if got, err := st.ChangePlan(ctx, "plan_1"); err != nil || string(got.Plan) != string(plan.Plan) || !got.ExpiresAt.Equal(plan.ExpiresAt) {
		t.Fatalf("ChangePlan = %+v, %v", got, err)
	}

	c := model.ChangeApproval{ID: model.NewID(model.PrefixChange), Op: proto.OpApplyFileChange, Technician: a.Technician,
		Client: "acme", Device: a.Device, AccessID: a.ID, GrantID: "grt", Session: "idp_s", PlanID: "plan_1", PlanDigest: "d1",
		State: model.ChangeAwaiting, RequestedAt: now, ExpiresAt: now.Add(model.ChangeApprovalWindow), Nonce: "n",
		RequestID: model.NewID(model.PrefixRequest)}
	if err := st.CreateChangeApproval(ctx, c); err != nil {
		t.Fatal(err)
	}
	wrong := c
	wrong.ID, wrong.Op = model.NewID(model.PrefixChange), proto.OpServiceRestart
	if err := st.CreateChangeApproval(ctx, wrong); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("an approval for %s: %v", proto.OpServiceRestart, err)
	}
	got, err := st.ChangeApproval(ctx, c.ID)
	if err != nil || got.GrantID != "grt" || !got.ExpiresAt.Equal(c.ExpiresAt) || got.Result != nil || !got.Approval().SameSigned(c.Approval()) {
		t.Fatalf("ChangeApproval = %+v, %v", got, err)
	}
	if found, err := st.ChangeApprovalFor(ctx, a.ID, "plan_1", proto.OpApplyFileChange, model.ChangeAwaiting); err != nil || found.ID != c.ID {
		t.Fatalf("ChangeApprovalFor = %+v, %v", found, err)
	}
	if _, err := st.ChangeApprovalFor(ctx, a.ID, "plan_1", proto.OpRollbackFileChange, model.ChangeAwaiting); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("ChangeApprovalFor another op: %v", err)
	}

	decided := now.Add(time.Minute)
	got, err = st.UpdateChangeApprovalTx(ctx, c.ID, func(x *model.ChangeApproval) error {
		if !model.ChangeAdvance(x.State, model.ChangeApproved) {
			return model.ErrConflict
		}
		x.State, x.DecidedAt, x.Credential = model.ChangeApproved, &decided, "cred-1"
		x.Assertion = []byte(`{"credential_id":"cred-1"}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if signed, err := got.SignedApproval(); err != nil || !signed.SameSigned(c.Approval()) || signed.Credential != "cred-1" {
		t.Fatalf("SignedApproval = %+v, %v", signed, err)
	}
	if open, _ := st.ChangeApprovalsOpen(ctx); len(open) != 1 {
		t.Fatalf("ChangeApprovalsOpen = %+v", open)
	}
	if _, err := st.UpdateChangeApprovalTx(ctx, c.ID, func(x *model.ChangeApproval) error {
		x.Result = json.RawMessage("{broken")
		return nil
	}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("a result that is not JSON: %v", err)
	}
	done := now.Add(2 * time.Minute)
	if _, err := st.UpdateChangeApprovalTx(ctx, c.ID, func(x *model.ChangeApproval) error {
		x.State, x.CompletedAt, x.Result = model.ChangeApplied, &done, json.RawMessage(`{"after_sha256":"x"}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ChangeApproval(ctx, c.ID)
	if got.State != model.ChangeApplied || string(got.Result) != `{"after_sha256":"x"}` || !got.CompletedAt.Equal(done) {
		t.Fatalf("after apply: %+v", got)
	}
	if open, _ := st.ChangeApprovalsOpen(ctx); len(open) != 0 {
		t.Fatalf("an applied change is still open: %+v", open)
	}
	if list, _ := st.ChangeApprovals(ctx, a.Technician, now); len(list) != 1 {
		t.Fatalf("ChangeApprovals since now = %+v", list)
	}
	if list, _ := st.ChangeApprovals(ctx, a.Technician, now.Add(time.Hour)); len(list) != 0 {
		t.Fatalf("a finished change is listed as recent after its window: %+v", list)
	}
}

func TestPurgeApprovalsKeepsWhatIsStillNeeded(t *testing.T) {
	st, a, now := approvalFixture(t)
	use := func(id string) {
		t.Helper()
		if err := st.RecordUnlockUse(ctx, id, model.UnlockActivity{Time: now, Op: proto.OpReadFile, Device: a.Device, Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	ended := newUnlock(t, st, "acme", now)
	use(ended.ID)
	if _, err := st.UpdateUnlockTx(ctx, ended.ID, func(u *model.Unlock) error {
		u.State, u.EndedAt = model.UnlockExpired, &now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	open := newUnlock(t, st, "acme", now)
	use(open.ID)

	for _, id := range []string{"plan_stale", "plan_kept"} {
		if err := st.CreateChangePlan(ctx, model.ChangePlanRecord{PlanID: id, AccessID: a.ID, Client: "acme", Device: a.Device,
			Technician: a.Technician, Digest: "d", Plan: json.RawMessage(`{}`), PreparedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateChangeApproval(ctx, model.ChangeApproval{ID: model.NewID(model.PrefixChange), Op: proto.OpApplyFileChange,
		Technician: a.Technician, Client: "acme", Device: a.Device, AccessID: a.ID, GrantID: "g", Session: "idp_s",
		PlanID: "plan_kept", PlanDigest: "d", State: model.ChangeAwaiting, RequestedAt: now, ExpiresAt: now.Add(time.Hour),
		Nonce: "n", RequestID: "req_1"}); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * time.Hour)
	if err := st.CreatePasskeyLink(ctx, model.PasskeyLink{ID: "pkl_old", Technician: "tech_alice", Hash: "h1",
		CreatedAt: old, ExpiresAt: old.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCompanionSession(ctx, model.CompanionSession{ID: "cps_old", Technician: "tech_alice", Credential: "c",
		Hash: "h2", CreatedAt: old, ExpiresAt: old.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	n, err := st.PurgeApprovals(ctx, now.Add(time.Minute))
	if err != nil || n != 4 {
		t.Fatalf("PurgeApprovals = %d, %v; want 4 rows: the ended unlock's activity, the stale plan, the link and the sign-in", n, err)
	}
	if acts, _ := st.UnlockActivity(ctx, ended.ID, 0); len(acts) != 0 {
		t.Fatalf("the ended unlock kept its activity: %+v", acts)
	}
	if acts, _ := st.UnlockActivity(ctx, open.ID, 0); len(acts) != 1 {
		t.Fatalf("the open unlock lost its activity: %+v", acts)
	}
	if _, err := st.ChangePlan(ctx, "plan_stale"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("the stale plan survived: %v", err)
	}
	if _, err := st.ChangePlan(ctx, "plan_kept"); err != nil {
		t.Fatalf("a plan an open approval names was purged: %v", err)
	}
}
