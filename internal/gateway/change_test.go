package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const cbs = `C:\Windows\Logs\CBS\CBS.log`

// grant puts an approved access request in the fixture's store, the way a
// consented request_access leaves one.
func (f *fixture) grant(t *testing.T, ops ...string) model.AccessRequest {
	t.Helper()
	decided := f.now.Add(-time.Minute)
	a := model.AccessRequest{ID: "acc_change", Client: "acme", Device: "dev_acme_srv01", Technician: "alice@msp",
		Session: "ses_alice", Purpose: "fix the vendor agent", State: model.AccessApproved,
		RequestedScope: []string{`C:\Windows\Logs`}, EffectiveScope: []string{`C:\Windows\Logs`},
		RequestedOperations: ops, EffectiveOperations: ops, RequestedAt: decided, DecidedAt: &decided,
		ExpiresAt: f.now.Add(30 * time.Minute), IdleTimeout: 10 * time.Minute, GrantID: "grt_1", Nonce: "n1", PolicyVersion: 1}
	if err := f.dir.CreateAccess(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *fixture) access(t *testing.T, id string) model.AccessRequest {
	t.Helper()
	a, err := f.dir.Access(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func planFrom(t *testing.T, text string) (id, digest string) {
	t.Helper()
	for _, field := range strings.Split(strings.SplitN(text, "\n", 2)[0], " | ") {
		k, v, _ := strings.Cut(field, ": ")
		switch strings.TrimSpace(k) {
		case "plan":
			id = v
		case "digest":
			digest = v
		}
	}
	if id == "" || digest == "" {
		t.Fatalf("no plan in:\n%s", text)
	}
	return id, digest
}

func TestPrepareApplyRollbackThroughTheGateway(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.grant(t, proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange)

	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "path": cbs, "content": "fixed\n", "reason": "ticket 42"})
	if isErr {
		t.Fatalf("prepare: %s", text)
	}
	planID, digest := planFrom(t, text)
	switch {
	case !strings.Contains(text, "Nothing has been written yet"):
		t.Errorf("prepare does not say the file is untouched:\n%s", text)
	case !strings.Contains(text, boundaryTag):
		t.Errorf("the diff is not inside the untrusted-data boundary:\n%s", text)
	case f.access(t, a.ID).PlanDigest != digest:
		t.Errorf("the grant records %q, not the prepared plan's digest", f.access(t, a.ID).PlanDigest)
	}

	// A digest the grant does not carry never reaches the machine.
	before := len(f.acme.requests())
	text, isErr = call(t, cs, proto.OpApplyFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID, "plan_digest": "digest-somethingelse"})
	if !isErr || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("apply with a foreign digest: %s", text)
	}
	if len(f.acme.requests()) != before {
		t.Error("a mismatched apply was sent to the machine anyway")
	}

	text, isErr = call(t, cs, proto.OpApplyFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID, "plan_digest": digest})
	if isErr || !strings.Contains(text, `"rollback_id"`) {
		t.Fatalf("apply: %s", text)
	}
	if d := f.access(t, a.ID).PlanDigest; d != "" {
		t.Errorf("the grant still carries a spent plan: %q", d)
	}
	// The plan is spent, so the same digest cannot be applied again.
	text, isErr = call(t, cs, proto.OpApplyFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID, "plan_digest": digest})
	if !isErr || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("replayed apply: %s", text)
	}
	text, isErr = call(t, cs, proto.OpRollbackFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID})
	if isErr || !strings.Contains(text, planID) {
		t.Fatalf("rollback: %s", text)
	}
}

func TestChangeToolsNeedAGrantThatIncludesTheOperation(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.grant(t, proto.OpReadFile) // a read-only grant
	calls := map[string]map[string]any{
		proto.OpPrepareFileChange:  {"path": cbs, "content": "x\n"},
		proto.OpApplyFileChange:    {"plan_id": "plan_x", "plan_digest": "d"},
		proto.OpRollbackFileChange: {"plan_id": "plan_x"},
		proto.OpServiceQuery:       {"name": "VendorService"},
		proto.OpServiceRestart:     {"name": "VendorService"},
		proto.OpListPrinters:       {},
	}
	for tool, args := range calls {
		args["device"], args["access_id"] = "dev_acme_srv01", a.ID
		before := len(f.acme.requests())
		text, isErr := call(t, cs, tool, args)
		if !isErr || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Errorf("%s under a read-only grant: %s", tool, text)
		}
		if len(f.acme.requests()) != before {
			t.Errorf("%s reached the machine without authority", tool)
		}
		if e := f.lastEntry(t, "acme"); e.Tool != tool || e.Result != audit.ResultDenied {
			t.Errorf("%s refusal was audited as %+v", tool, e)
		}
	}
}

// A change call with no access grant at all is refused and audited; the
// endpoint refuses it too, which the fstools tests cover.
func TestChangeToolsWithoutAnAccessGrant(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{
		"device": "dev_acme_srv01", "path": cbs, "content": "x\n", "access_id": ""})
	if !isErr || !strings.Contains(text, proto.ErrConsentRequired) {
		t.Fatalf("prepare with no grant: %s", text)
	}
}

func TestServiceToolsRunUnderAGrant(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.grant(t, proto.OpServiceQuery, proto.OpServiceRestart)
	text, isErr := call(t, cs, proto.OpServiceQuery, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "name": "VendorService"})
	if isErr || !strings.Contains(text, proto.ServiceRunning) {
		t.Fatalf("service_query: %s", text)
	}
	text, isErr = call(t, cs, proto.OpServiceRestart, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "name": "VendorService"})
	if isErr || !strings.Contains(text, `"restarted":true`) {
		t.Fatalf("service_restart: %s", text)
	}
	if e := f.lastEntry(t, "acme"); e.Tool != proto.OpServiceRestart || !strings.Contains(string(e.Change), "VendorService") {
		t.Errorf("restart audit entry %+v", e)
	}
}

// The audit entry must carry what changed, and its hashes must be the ones the
// endpoint reported for the bytes it returned.
func TestChangeCallsAreAuditedWithTheirPlan(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	a := f.grant(t, proto.OpPrepareFileChange, proto.OpApplyFileChange)
	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "path": cbs, "content": "fixed\n"})
	if isErr {
		t.Fatalf("prepare: %s", text)
	}
	planID, digest := planFrom(t, text)
	if _, isErr := call(t, cs, proto.OpApplyFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID, "plan_digest": digest}); isErr {
		t.Fatal("apply failed")
	}
	var applied audit.Entry
	for _, e := range f.entries(t, "acme") {
		if e.Tool == proto.OpApplyFileChange && e.Result == audit.ResultOK {
			applied = e
		}
	}
	var change proto.ChangeMeta
	if err := json.Unmarshal(applied.Change, &change); err != nil {
		t.Fatalf("audit entry has no change metadata: %+v", applied)
	}
	switch {
	case change.PlanID != planID || change.PlanDigest != digest:
		t.Errorf("audit records plan %+v", change)
	case change.BeforeSHA256 == "" || change.AfterSHA256 == "" || change.BytesChanged == 0:
		t.Errorf("audit records no hashes or byte count: %+v", change)
	case applied.SHA256 == "" || applied.Bytes == 0:
		t.Errorf("audit entry does not cover the result bytes: %+v", applied)
	}
	// The chain still verifies with the new field in the entry.
	v, err := f.store.Verify(context.Background(), "acme")
	if err != nil || !v.OK {
		t.Fatalf("audit chain: %+v %v", v, err)
	}
}

// TestPrepareSaysWhenTheMachineIsReviewing: an endpoint that shows the plan to
// the person there answers prepare at once. The relay tells the assistant that
// the review is pending and that apply is refused until it is approved, and
// the apply's audit entry names who approved it.
func TestPrepareSaysWhenTheMachineIsReviewing(t *testing.T) {
	f := newFixture(t)
	f.acme.review = true
	cs := f.connect(t, bearerACME)
	a := f.grant(t, proto.OpPrepareFileChange, proto.OpApplyFileChange)
	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "path": cbs, "content": "fixed\n", "reason": "ticket 42"})
	if isErr {
		t.Fatalf("prepare: %s", text)
	}
	for _, want := range []string{"review: awaiting", "person at the machine", proto.ErrConsentRequired} {
		if !strings.Contains(text, want) {
			t.Errorf("prepare says:\n%s\nwant it to mention %q", text, want)
		}
	}
	planID, digest := planFrom(t, text)
	if out, isErr := call(t, cs, proto.OpApplyFileChange, map[string]any{
		"device": "dev_acme_srv01", "access_id": a.ID, "plan_id": planID, "plan_digest": digest}); isErr {
		t.Fatalf("apply: %s", out)
	}
	var change proto.ChangeMeta
	for _, e := range f.entries(t, "acme") {
		if e.Tool == proto.OpApplyFileChange && e.Result == audit.ResultOK {
			if err := json.Unmarshal(e.Change, &change); err != nil {
				t.Fatal(err)
			}
		}
	}
	if change.Approver != `ACME\sam` {
		t.Errorf("the apply's audit entry records approver %q, want the person who approved it", change.Approver)
	}
}

func TestRequestAccessValidatesTheOperationsAsked(t *testing.T) {
	f := newFixture(t)
	cs := f.connect(t, bearerACME)
	args := func(ops ...string) map[string]any {
		m := map[string]any{"device": "dev_acme_srv01", "purpose": "fix vendor agent",
			"paths": []string{`C:\Windows\Logs`}, "duration_minutes": 10}
		if ops != nil {
			m["operations"] = ops
		}
		return m
	}
	text, isErr := call(t, cs, proto.OpRequestAccess, args("write_everything"))
	if !isErr || !strings.Contains(text, proto.ErrBadRequest) {
		t.Fatalf("unknown operation accepted: %s", text)
	}
	text, isErr = call(t, cs, proto.OpRequestAccess, args())
	if isErr {
		t.Fatalf("default operations: %s", text)
	}
	var a model.AccessRequest
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.RequestedOperations) != 1 || a.RequestedOperations[0] != proto.OpReadFile {
		t.Errorf("default operations are %v", a.RequestedOperations)
	}
	text, isErr = call(t, cs, proto.OpRequestAccess, args(proto.OpApplyFileChange, proto.OpServiceRestart))
	if isErr {
		t.Fatalf("change operations: %s", text)
	}
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{proto.OpApplyFileChange, proto.OpServiceRestart, proto.OpPrepareFileChange} {
		if !strings.Contains(strings.Join(a.RequestedOperations, ","), want) {
			t.Errorf("requested operations %v lack %s", a.RequestedOperations, want)
		}
	}
}

func TestChangeOperationsHelper(t *testing.T) {
	if ops, err := changeOperations(nil); err != nil || len(ops) != 1 || ops[0] != proto.OpReadFile {
		t.Errorf("default = %v, %v", ops, err)
	}
	if ops, err := changeOperations([]string{proto.OpApplyFileChange, proto.OpApplyFileChange}); err != nil ||
		len(ops) != 2 || ops[1] != proto.OpPrepareFileChange {
		t.Errorf("apply implies prepare: %v, %v", ops, err)
	}
	for _, bad := range []string{"ping", "request_access", "end_access", "rm -rf", ""} {
		if _, err := changeOperations([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
