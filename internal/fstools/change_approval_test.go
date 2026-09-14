package fstools

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Technician grants (Slice 6). A grant the endpoint approved on a technician
// unlock carries the unlock's ID. Every write under it needs the technician's
// signed approval of exactly that write, and the person at the machine is
// asked only when the client's policy says so.

// technicianFixture is a change fixture whose grant came from a technician
// unlock, and, with endpointConsent, was approved at the machine as well.
func technicianFixture(t *testing.T, approver ChangeApprover, endpointConsent bool) *changeFixture {
	t.Helper()
	f := newChangeFixture(t, approver)
	f.cap.Unlock, f.cap.EndpointConsent = "unl_one", endpointConsent
	return f
}

// approval is the technician's signed approval of op on plan p under the
// fixture's grant, as the relay's gate releases it.
func (f *changeFixture) approval(op string, p proto.PrepareFileChangeResult, rollbackID string) *proto.TechnicianApproval {
	now := time.Now().UTC()
	return &proto.TechnicianApproval{Kind: proto.ApprovalChange, ID: "chg_one", Technician: f.cap.Technician, Client: f.cap.Client,
		Device: f.cap.Device, AccessID: f.cap.AccessID, GrantID: f.cap.GrantID, Op: op, PlanID: p.PlanID, PlanDigest: p.PlanDigest,
		RollbackID: rollbackID, Nonce: "nonce-one", ExpiresAt: now.Add(10 * time.Minute),
		Credential: "Y3JlZGVudGlhbC1vbmU", ApprovedAt: now}
}

func (f *changeFixture) applyWith(t *testing.T, p proto.PrepareFileChangeResult, a *proto.TechnicianApproval) *proto.Response {
	t.Helper()
	return f.call(t, proto.OpApplyFileChange, proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest, Approval: a})
}

// untouched fails unless the target still holds exactly the original bytes
// with its original modification time, and no rollback copy was saved: the
// proof that nothing was written.
func (f *changeFixture) untouched(t *testing.T, modTime time.Time) {
	t.Helper()
	b, err := os.ReadFile(f.file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte(original)) {
		t.Fatalf("the target was written: %q", b)
	}
	if fi, err := os.Stat(f.file); err != nil || !fi.ModTime().Equal(modTime) {
		t.Fatalf("the target's modification time changed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(f.store, rollbackDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("a rollback copy was saved: %s", e.Name())
	}
}

func modTime(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

// Security property: under a technician grant nothing is written without the
// technician's approval, whether or not a consent window could have reviewed
// the plan.
func TestTechnicianApplyWithoutAnApprovalWritesNothing(t *testing.T) {
	for name, approver := range map[string]ChangeApprover{"no consent window": nil, "a consent window": &pendingApprover{}} {
		t.Run(name, func(t *testing.T) {
			f := technicianFixture(t, approver, false)
			p := f.prepare(t, proposed)
			before := modTime(t, f.file)
			resp := f.apply(t, p)
			wantError(t, resp, proto.ErrApprovalRequired)
			if strings.Contains(resp.Error.Message, "person at the machine") {
				t.Errorf("a technician grant's refusal sends the caller to the machine: %q", resp.Error.Message)
			}
			f.untouched(t, before)
			if rec, err := f.x.changes.loadPlan(p.PlanID); err != nil || rec.State != planStaged {
				t.Errorf("the plan is %v after a refused apply (%v)", rec, err)
			}
		})
	}
}

// Security property: an approval releases exactly the write it names. One
// for another plan, digest, grant, device, technician or operation, an
// unsigned one, or an expired one releases nothing.
func TestTechnicianApplyRefusesAnApprovalThatDoesNotBindIt(t *testing.T) {
	f := technicianFixture(t, nil, false)
	p := f.prepare(t, proposed)
	q := f.prepare(t, "level=warn\n") // another plan under the same grant
	before := modTime(t, f.file)
	skew := proto.ApprovalClockSkew
	for name, mutate := range map[string]func(a *proto.TechnicianApproval){
		"an unlock":                  func(a *proto.TechnicianApproval) { a.Kind = proto.ApprovalUnlock },
		"no approval ID":             func(a *proto.TechnicianApproval) { a.ID = "" },
		"unsigned: no credential":    func(a *proto.TechnicianApproval) { a.Credential = "" },
		"unsigned: no approval time": func(a *proto.TechnicianApproval) { a.ApprovedAt = time.Time{} },
		"a rollback":                 func(a *proto.TechnicianApproval) { a.Op = proto.OpRollbackFileChange },
		"another technician":         func(a *proto.TechnicianApproval) { a.Technician = "bob" },
		"another client":             func(a *proto.TechnicianApproval) { a.Client = "globex" },
		"another device":             func(a *proto.TechnicianApproval) { a.Device = "dev_two" },
		"another access request":     func(a *proto.TechnicianApproval) { a.AccessID = "acc_two" },
		"another grant":              func(a *proto.TechnicianApproval) { a.GrantID = "grt_two" },
		"another plan":               func(a *proto.TechnicianApproval) { a.PlanID, a.PlanDigest = q.PlanID, q.PlanDigest },
		"another digest":             func(a *proto.TechnicianApproval) { a.PlanDigest = strings.Repeat("0", 64) },
		"a rollback copy":            func(a *proto.TechnicianApproval) { a.RollbackID = "rb_" + strings.Repeat("0", 20) },
		"expired beyond the skew":    func(a *proto.TechnicianApproval) { a.ExpiresAt = time.Now().Add(-skew - time.Minute) },
	} {
		a := f.approval(proto.OpApplyFileChange, p, "")
		mutate(a)
		resp := f.applyWith(t, p, a)
		if resp.Error == nil || resp.Error.Code != proto.ErrApprovalRequired {
			t.Fatalf("%s: got %+v; want %s", name, resp.Error, proto.ErrApprovalRequired)
		}
		f.untouched(t, before)
	}
	// An approval that lapsed within the clock skew still releases the write.
	a := f.approval(proto.OpApplyFileChange, p, "")
	a.ExpiresAt = time.Now().Add(-skew + 30*time.Second)
	result[proto.ApplyFileChangeResult](t, f.applyWith(t, p, a))
	if readBack(t, f.file) != proposed {
		t.Fatal("the approved change was not applied")
	}
}

func TestTechnicianApplyRecordsTheApproval(t *testing.T) {
	f := technicianFixture(t, nil, false)
	p := f.prepare(t, proposed)
	if p.Approved || p.Review != "" {
		t.Fatalf("prepare under a technician grant claims a review: approved=%t review=%q", p.Approved, p.Review)
	}
	a := f.approval(proto.OpApplyFileChange, p, "")
	args := proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest, Approval: a}
	resp := f.callID(t, proto.OpApplyFileChange, args, "req_release")
	result[proto.ApplyFileChangeResult](t, resp)
	if readBack(t, f.file) != proposed {
		t.Fatal("the approved change was not applied")
	}
	if m := resp.Meta.Change; m == nil || m.ApprovalID != a.ID || m.Approver != a.ApproverLabel() {
		t.Errorf("the audit metadata is %+v; want approval %s by %q", m, a.ID, a.ApproverLabel())
	}
	if rec, err := f.x.changes.loadPlan(p.PlanID); err != nil || rec.Approver != a.ApproverLabel() || rec.ApprovalID != a.ID {
		t.Errorf("the plan records approver %q approval %q (%v)", rec.Approver, rec.ApprovalID, err)
	}

	// A repeated release by the same request ID returns the journalled result,
	// approval included, and writes nothing: its first attempt was checked.
	stat := modTime(t, f.file)
	args.Approval = nil
	again := f.callID(t, proto.OpApplyFileChange, args, "req_release")
	if out := result[proto.ApplyFileChangeResult](t, again); !out.Replayed {
		t.Error("the repeated release did not report itself as a replay")
	}
	if m := again.Meta.Change; m == nil || m.ApprovalID != a.ID {
		t.Errorf("the replay's audit metadata is %+v", m)
	}
	if !modTime(t, f.file).Equal(stat) {
		t.Error("the replay wrote the file again")
	}
}

// When the client's policy asks the person at the machine as well, a change
// needs both approvals, and the audit names both approvers.
func TestEndpointConsentGrantNeedsBothApprovals(t *testing.T) {
	a := &pendingApprover{}
	f := technicianFixture(t, a, true)
	reviewed := f.watchReviews()
	p := f.prepare(t, proposed)
	if p.Review != reviewAwaiting {
		t.Fatalf("prepare returned review %q; want the plan shown at the machine", p.Review)
	}
	before := modTime(t, f.file)
	tech := f.approval(proto.OpApplyFileChange, p, "")

	resp := f.applyWith(t, p, tech)
	wantError(t, resp, proto.ErrConsentRequired)
	if strings.Contains(resp.Error.Message, "ask them") {
		t.Errorf("a technician grant's refusal tells the caller to ask the person at the machine: %q", resp.Error.Message)
	}
	f.untouched(t, before)

	a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, Approver: `ACME\sam`, PlanDigest: p.PlanDigest})
	waitReview(t, reviewed, p.PlanID)
	wantError(t, f.apply(t, p), proto.ErrApprovalRequired) // the machine's approval alone
	f.untouched(t, before)

	resp = f.applyWith(t, p, tech)
	result[proto.ApplyFileChangeResult](t, resp)
	if readBack(t, f.file) != proposed {
		t.Fatal("the change approved twice was not applied")
	}
	want := tech.ApproverLabel() + `; at the machine: ACME\sam`
	if m := resp.Meta.Change; m == nil || m.Approver != want || m.ApprovalID != tech.ID {
		t.Errorf("the audit metadata is %+v; want approver %q", m, want)
	}
}

// The person at the machine reviews a plan only where they approved the
// grant: a legacy grant, or a technician grant whose client's policy asks
// them. Under any other technician grant prepare prompts nobody, and needs no
// consent window at all.
func TestPlanReviewOnlyWhereThePersonAtTheMachineApproves(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		unlock, endpointConsent bool
		reviewed                bool
	}{
		{"legacy grant", false, false, true},
		{"technician grant", true, false, false},
		{"technician grant with endpoint consent", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &pendingApprover{}
			f := newChangeFixture(t, a)
			if tc.unlock {
				f.cap.Unlock, f.cap.EndpointConsent = "unl_one", tc.endpointConsent
			}
			p := f.prepare(t, proposed)
			a.mu.Lock()
			shown := len(a.seen)
			a.mu.Unlock()
			if got := shown > 0; got != tc.reviewed || (p.Review == reviewAwaiting) != tc.reviewed {
				t.Errorf("reviews started %d, review %q; want reviewed=%t", shown, p.Review, tc.reviewed)
			}
		})
	}
	t.Run("a technician grant prepares with no consent window running", func(t *testing.T) {
		f := technicianFixture(t, &pendingApprover{err: errors.New("no local consent window is watching this grant")}, false)
		f.prepare(t, proposed)
	})
}

// Security property: a rollback writes, so it needs a technician approval of
// its own; the apply's approval, or one for another copy, plan or time,
// restores nothing.
func TestTechnicianRollbackNeedsItsOwnApproval(t *testing.T) {
	f := technicianFixture(t, nil, false)
	p := f.prepare(t, proposed)
	applyApproval := f.approval(proto.OpApplyFileChange, p, "")
	applied := result[proto.ApplyFileChangeResult](t, f.applyWith(t, p, applyApproval))
	rollback := func(a *proto.TechnicianApproval) *proto.Response {
		return f.call(t, proto.OpRollbackFileChange, proto.RollbackFileChangeArgs{PlanID: p.PlanID, RollbackID: applied.RollbackID, Approval: a})
	}
	rbApproval := func() *proto.TechnicianApproval {
		a := f.approval(proto.OpRollbackFileChange, p, applied.RollbackID)
		a.ID = "chg_two"
		return a
	}
	stat := modTime(t, f.file)
	for name, a := range map[string]*proto.TechnicianApproval{
		"none":                 nil,
		"the apply's approval": applyApproval,
		"another rollback copy": func() *proto.TechnicianApproval {
			a := rbApproval()
			a.RollbackID = "rb_" + strings.Repeat("0", 20)
			return a
		}(),
		"another digest": func() *proto.TechnicianApproval { a := rbApproval(); a.PlanDigest = strings.Repeat("0", 64); return a }(),
		"another grant":  func() *proto.TechnicianApproval { a := rbApproval(); a.GrantID = "grt_two"; return a }(),
		"expired beyond the skew": func() *proto.TechnicianApproval {
			a := rbApproval()
			a.ExpiresAt = time.Now().Add(-time.Hour)
			return a
		}(),
	} {
		if resp := rollback(a); resp.Error == nil || resp.Error.Code != proto.ErrApprovalRequired {
			t.Fatalf("%s: got %+v; want %s", name, resp.Error, proto.ErrApprovalRequired)
		}
		if readBack(t, f.file) != proposed || !modTime(t, f.file).Equal(stat) {
			t.Fatalf("%s: a refused rollback wrote", name)
		}
	}
	rb := rbApproval()
	resp := rollback(rb)
	result[proto.RollbackFileChangeResult](t, resp)
	if readBack(t, f.file) != original {
		t.Fatal("the approved rollback did not restore the file")
	}
	if m := resp.Meta.Change; m == nil || m.ApprovalID != rb.ID || m.Approver != rb.ApproverLabel() {
		t.Errorf("the rollback's audit metadata is %+v; want approval %s", m, rb.ID)
	}

	t.Run("an approval of the plan's own copy, named by neither", func(t *testing.T) {
		f := technicianFixture(t, nil, false)
		p := f.prepare(t, proposed)
		result[proto.ApplyFileChangeResult](t, f.applyWith(t, p, f.approval(proto.OpApplyFileChange, p, "")))
		result[proto.RollbackFileChangeResult](t, f.call(t, proto.OpRollbackFileChange,
			proto.RollbackFileChangeArgs{PlanID: p.PlanID, Approval: f.approval(proto.OpRollbackFileChange, p, "")}))
		if readBack(t, f.file) != original {
			t.Fatal("the rollback did not restore the file")
		}
	})
}

// An apply interrupted after the rename is finished by a retry of the same
// request ID even once its approval has lapsed, like the plan's own expiry,
// but only with an approval that still binds it; and finishing it names the
// approvers once.
func TestTechnicianApplyResumesAfterAnInterruption(t *testing.T) {
	a := &pendingApprover{}
	f := technicianFixture(t, a, true)
	reviewed := f.watchReviews()
	p := f.prepare(t, proposed)
	a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, Approver: `ACME\sam`, PlanDigest: p.PlanDigest})
	waitReview(t, reviewed, p.PlanID)
	tech := f.approval(proto.OpApplyFileChange, p, "")
	args := proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest, Approval: tech}
	applied := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange, args, "req_half"))
	want := tech.ApproverLabel() + `; at the machine: ACME\sam`

	// Rewind the plan and the journal to the moment after the rename.
	rec, err := f.x.changes.loadPlan(p.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	rec.State, rec.RollbackID, rec.RollbackSHA = planStaged, "", ""
	rec.AppliedAt, rec.RollbackUntil = time.Time{}, time.Time{}
	if err := f.x.changes.savePlan(rec); err != nil {
		t.Fatal(err)
	}
	j := &journalRecord{Version: storeVersion, RequestID: "req_half", Op: proto.OpApplyFileChange, PlanID: p.PlanID,
		State: journalIntent, RollbackID: applied.RollbackID, At: time.Now().UTC()}
	if err := f.x.changes.saveJournal(j); err != nil {
		t.Fatal(err)
	}

	lapsed := *tech
	lapsed.ExpiresAt = time.Now().Add(-time.Hour)
	unbound := lapsed
	unbound.GrantID = "grt_two"
	args.Approval = &unbound
	wantError(t, f.callID(t, proto.OpApplyFileChange, args, "req_half"), proto.ErrApprovalRequired)

	args.Approval = &lapsed
	resp := f.callID(t, proto.OpApplyFileChange, args, "req_half")
	if out := result[proto.ApplyFileChangeResult](t, resp); !out.Replayed || out.RollbackID != applied.RollbackID {
		t.Errorf("the resumed apply reported %+v", out)
	}
	if m := resp.Meta.Change; m == nil || m.Approver != want || m.ApprovalID != tech.ID {
		t.Errorf("the resumed apply's audit metadata is %+v; want approver %q", m, want)
	}
	if rec, err := f.x.changes.loadPlan(p.PlanID); err != nil || rec.Approver != want {
		t.Errorf("the plan records approver %q (%v); want %q", rec.Approver, err, want)
	}
}

// A restart cannot be named by a technician approval yet, so a grant that
// came from an unlock cannot restart anything, whatever its operations say.
func TestServiceRestartIsRefusedUnderATechnicianGrant(t *testing.T) {
	f := technicianFixture(t, nil, false)
	f.pol.ServiceAllow = []string{"VendorService"}
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "VendorService"}), proto.ErrApprovalRequired)
}
