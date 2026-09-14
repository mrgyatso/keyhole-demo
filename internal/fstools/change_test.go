package fstools

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// The change tests drive the executor the way the runner does: a policy whose
// allow rules are the grant's paths, and a capability the runner has already
// matched against its live grant cache.

const (
	original = "level=info\nretries=3\ntimeout=30\n"
	proposed = "level=debug\nretries=5\ntimeout=30\n"
)

type changeFixture struct {
	x        *Executor
	root     string
	file     string
	store    string
	cap      proto.Capability
	pol      proto.Policy
	requests int
}

func newChangeFixture(t *testing.T, approver ChangeApprover, ops ...string) *changeFixture {
	t.Helper()
	root := tempRoot(t)
	store := filepath.Join(t.TempDir(), "change")
	if len(ops) == 0 {
		ops = []string{proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange,
			proto.OpServiceQuery, proto.OpServiceRestart, proto.OpReadFile}
	}
	f := &changeFixture{
		x:     New(Options{ChangeDir: store, PlanApprover: approver}),
		root:  root,
		file:  filepath.Join(root, "config.json"),
		store: store,
		cap: proto.Capability{GrantID: "grt_one", AccessID: "acc_one", Nonce: "n", Client: "acme",
			Device: "dev_one", Technician: "alice", Operations: ops, Paths: []string{root},
			IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(30 * time.Minute).UTC(), PolicyVersion: 1},
		pol: testPolicy(rootRule(root)),
	}
	writeFile(t, f.file, original)
	return f
}

// call runs one op under the fixture's capability, with a fresh request ID.
func (f *changeFixture) call(t *testing.T, op string, args any) *proto.Response {
	t.Helper()
	f.requests++
	return f.callID(t, op, args, "req_"+itoa(f.requests))
}

func (f *changeFixture) callID(t *testing.T, op string, args any, id string) *proto.Response {
	t.Helper()
	req := request(t, op, args, f.pol)
	req.ID, req.Caller.Tech = id, f.cap.Technician
	cap := f.cap
	req.Capability = &cap
	// The runner's context for one request ends when the request does, so
	// nothing a change op starts may depend on it afterwards.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return f.x.Execute(ctx, req)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (f *changeFixture) prepare(t *testing.T, content string) proto.PrepareFileChangeResult {
	t.Helper()
	resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{Path: f.file, Content: content, Reason: "ticket 42"})
	return result[proto.PrepareFileChangeResult](t, resp)
}

func (f *changeFixture) apply(t *testing.T, p proto.PrepareFileChangeResult) *proto.Response {
	t.Helper()
	return f.call(t, proto.OpApplyFileChange, proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest})
}

func readBack(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareStagesWithoutTouchingTheTarget(t *testing.T) {
	f := newChangeFixture(t, nil)
	before, err := os.Stat(f.file)
	if err != nil {
		t.Fatal(err)
	}
	p := f.prepare(t, proposed)
	switch {
	case p.PlanID == "" || p.PlanDigest == "":
		t.Fatalf("plan has no identity: %+v", p)
	case p.Before.SHA256 != hashBytes([]byte(original)):
		t.Errorf("before hash %s", p.Before.SHA256)
	case p.AfterSHA256 != hashBytes([]byte(proposed)):
		t.Errorf("after hash %s", p.AfterSHA256)
	case p.Before.Identity.Zero():
		t.Error("the plan records no file identity")
	case !strings.Contains(p.Diff, "-level=info") || !strings.Contains(p.Diff, "+level=debug"):
		t.Errorf("diff does not show the change:\n%s", p.Diff)
	case strings.Contains(p.Diff, "timeout=30\n+timeout"):
		t.Errorf("diff repeats unchanged lines:\n%s", p.Diff)
	case p.Approved:
		t.Error("the plan claims approval with no approver configured")
	}
	if got := readBack(t, f.file); got != original {
		t.Errorf("prepare changed the file: %q", got)
	}
	after, err := os.Stat(f.file)
	if err != nil || !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("prepare touched the file's modification time")
	}
	if p.PlanDigest != planDigest(p.Before.Path, p.Before.SHA256, p.AfterSHA256, p.PlanID) {
		t.Error("the digest does not cover the path, both hashes and the plan ID")
	}
}

func TestApplyAndRollbackRoundTrip(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	resp := f.apply(t, p)
	applied := result[proto.ApplyFileChangeResult](t, resp)
	switch {
	case readBack(t, f.file) != proposed:
		t.Fatalf("apply did not write the staged content: %q", readBack(t, f.file))
	case applied.BeforeSHA256 != hashBytes([]byte(original)) || applied.AfterSHA256 != hashBytes([]byte(proposed)):
		t.Errorf("apply reported %+v", applied)
	case applied.RollbackID == "" || applied.RollbackPath == "":
		t.Error("apply saved no rollback copy")
	case applied.Replayed:
		t.Error("a first apply reported itself as a replay")
	}
	if b, err := os.ReadFile(applied.RollbackPath); err != nil || string(b) != original {
		t.Errorf("rollback copy: %v %q", err, b)
	}
	// The audit metadata must describe what is actually on disk.
	if m := resp.Meta.Change; m == nil || m.AfterSHA256 != hashBytes([]byte(readBack(t, f.file))) || m.BytesChanged != int64(len(proposed)) {
		t.Errorf("change metadata %+v does not match the file", m)
	}
	if resp.Meta.SHA256 != hashBytes(resp.Result) || resp.Meta.Bytes != int64(len(resp.Result)) {
		t.Error("Meta.Bytes/SHA256 do not cover the result bytes")
	}

	rb := result[proto.RollbackFileChangeResult](t, f.call(t, proto.OpRollbackFileChange,
		proto.RollbackFileChangeArgs{PlanID: p.PlanID, RollbackID: applied.RollbackID}))
	if readBack(t, f.file) != original {
		t.Fatalf("rollback did not restore the file: %q", readBack(t, f.file))
	}
	if rb.AfterSHA256 != hashBytes([]byte(original)) || rb.BeforeSHA256 != hashBytes([]byte(proposed)) {
		t.Errorf("rollback reported %+v", rb)
	}
	// A plan is single use in both directions.
	wantError(t, f.apply(t, p), proto.ErrStalePlan)
	wantError(t, f.call(t, proto.OpRollbackFileChange, proto.RollbackFileChangeArgs{PlanID: p.PlanID}), proto.ErrStalePlan)
}

func TestRollbackRefusesWhenTheFileChangedAgain(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	applied := result[proto.ApplyFileChangeResult](t, f.apply(t, p))
	writeFile(t, f.file, "someone else edited this\n")
	wantError(t, f.call(t, proto.OpRollbackFileChange,
		proto.RollbackFileChangeArgs{PlanID: p.PlanID, RollbackID: applied.RollbackID}), proto.ErrStalePlan)
	if got := readBack(t, f.file); got != "someone else edited this\n" {
		t.Errorf("rollback discarded another change: %q", got)
	}
}

func TestChangeOpsRefuseWithoutACapability(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	args := map[string]any{
		proto.OpPrepareFileChange:  proto.PrepareFileChangeArgs{Path: f.file, Content: proposed},
		proto.OpApplyFileChange:    proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest},
		proto.OpRollbackFileChange: proto.RollbackFileChangeArgs{PlanID: p.PlanID},
		proto.OpServiceQuery:       proto.ServiceQueryArgs{Name: "VendorService"},
		proto.OpServiceRestart:     proto.ServiceRestartArgs{Name: "VendorService"},
	}
	for op, a := range args {
		// A legacy client-bound request carries no capability at all.
		resp := run(t, f.x, op, a, f.pol)
		wantError(t, resp, proto.ErrConsentRequired)
		// A grant that does not include the op.
		narrow := *f
		narrow.cap.Operations = []string{proto.OpReadFile}
		wantError(t, narrow.call(t, op, a), proto.ErrNotAllowed)
	}
	if got := readBack(t, f.file); got != original {
		t.Errorf("a refused change still wrote: %q", got)
	}
}

func TestChangeOpsAreUnavailableWithoutAChangeStore(t *testing.T) {
	f := newChangeFixture(t, nil)
	f.x = New(Options{}) // no ChangeDir
	wantError(t, f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{Path: f.file, Content: proposed}), proto.ErrUnsupported)
}

func TestApplyRefusesAWrongDigestOrAnotherGrant(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	wantError(t, f.call(t, proto.OpApplyFileChange,
		proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: strings.Repeat("0", 64)}), proto.ErrStalePlan)
	wantError(t, f.call(t, proto.OpApplyFileChange,
		proto.ApplyFileChangeArgs{PlanID: "plan_" + strings.Repeat("f", 20), PlanDigest: p.PlanDigest}), proto.ErrStalePlan)
	wantError(t, f.call(t, proto.OpApplyFileChange,
		proto.ApplyFileChangeArgs{PlanID: "../../etc/passwd", PlanDigest: p.PlanDigest}), proto.ErrBadRequest)

	other := *f
	other.cap.GrantID = "grt_two"
	wantError(t, other.apply(t, p), proto.ErrGrantInvalid)
	if got := readBack(t, f.file); got != original {
		t.Errorf("a refused apply still wrote: %q", got)
	}
}

func TestApplyRefusesAStalePlan(t *testing.T) {
	t.Run("content changed", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		p := f.prepare(t, proposed)
		writeFile(t, f.file, "changed underneath\n")
		wantError(t, f.apply(t, p), proto.ErrStalePlan)
		if got := readBack(t, f.file); got != "changed underneath\n" {
			t.Errorf("a stale apply wrote anyway: %q", got)
		}
	})
	t.Run("file replaced with identical content", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		p := f.prepare(t, proposed)
		// Same bytes, different file: only the recorded identity catches this.
		if err := os.Remove(f.file); err != nil {
			t.Fatal(err)
		}
		writeFile(t, f.file, original)
		wantError(t, f.apply(t, p), proto.ErrStalePlan)
	})
	t.Run("expired plan", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		p := f.prepare(t, proposed)
		rec, err := f.x.changes.loadPlan(p.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		rec.Plan.ExpiresAt = time.Now().Add(-time.Minute)
		if err := f.x.changes.savePlan(rec); err != nil {
			t.Fatal(err)
		}
		wantError(t, f.apply(t, p), proto.ErrStalePlan)
	})
	t.Run("expectation fails at prepare", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{
			Path: f.file, Content: proposed, ExpectSHA256: strings.Repeat("0", 64)})
		wantError(t, resp, proto.ErrStalePlan)
	})
}

func TestApplyIsIdempotentByRequestID(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	args := proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest}
	first := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange, args, "req_retry"))
	stat, err := os.Stat(f.file)
	if err != nil {
		t.Fatal(err)
	}
	second := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange, args, "req_retry"))
	if !second.Replayed || second.RollbackID != first.RollbackID || second.AfterSHA256 != first.AfterSHA256 {
		t.Errorf("replay returned a different result: %+v vs %+v", second, first)
	}
	again, err := os.Stat(f.file)
	if err != nil || !again.ModTime().Equal(stat.ModTime()) {
		t.Error("the replay wrote the file a second time")
	}
	// A different request ID for a plan that is already applied is stale.
	wantError(t, f.callID(t, proto.OpApplyFileChange, args, "req_other"), proto.ErrStalePlan)
	// The same request ID cannot be reused for a different op.
	wantError(t, f.callID(t, proto.OpRollbackFileChange, proto.RollbackFileChangeArgs{PlanID: p.PlanID}, "req_retry"), proto.ErrBadRequest)
}

func TestConcurrentAppliesOfOnePlanApplyItOnce(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	args := proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest}
	var wg sync.WaitGroup
	resps := make([]*proto.Response, 2)
	for i := range resps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resps[i] = f.callID(t, proto.OpApplyFileChange, args, "req_race"+itoa(i))
		}()
	}
	wg.Wait()
	ok := 0
	for _, resp := range resps {
		if resp.OK {
			ok++
			continue
		}
		switch resp.Error.Code {
		case proto.ErrConflict, proto.ErrStalePlan:
		default:
			t.Errorf("second apply failed with %+v; want a conflict or a stale plan", resp.Error)
		}
	}
	if ok != 1 {
		t.Errorf("%d of 2 concurrent applies succeeded; want exactly 1", ok)
	}
	if got := readBack(t, f.file); got != proposed {
		t.Errorf("file is %q after the race", got)
	}
}

// A crash between the temporary write and the rename leaves the original file
// and a named temporary: the next attempt with the same request ID applies
// cleanly, and startup cleanup removes the leftover.
func TestPowerLossBeforeTheRename(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	temp := filepath.Join(f.root, tempPrefix+p.PlanID+tempSuffix)
	writeFile(t, temp, "half written")
	j := &journalRecord{Version: storeVersion, RequestID: "req_crash", Op: proto.OpApplyFileChange,
		PlanID: p.PlanID, State: journalIntent, TempPath: temp, At: time.Now().UTC()}
	if err := f.x.changes.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	applied := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange,
		proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest}, "req_crash"))
	if applied.Replayed {
		t.Error("an interrupted apply that never renamed was reported as already done")
	}
	if got := readBack(t, f.file); got != proposed {
		t.Fatalf("the retried apply did not write: %q", got)
	}
	if _, err := os.Stat(temp); err == nil {
		t.Error("the temporary file survived the retry")
	}
}

// A crash after the rename but before the journal was committed: the next
// attempt must finish the bookkeeping and never write a second time.
func TestPowerLossAfterTheRename(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	args := proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest}
	applied := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange, args, "req_half"))
	// Rewind the journal and the plan to the moment after the rename.
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
	stat, err := os.Stat(f.file)
	if err != nil {
		t.Fatal(err)
	}
	out := result[proto.ApplyFileChangeResult](t, f.callID(t, proto.OpApplyFileChange, args, "req_half"))
	switch {
	case !out.Replayed:
		t.Error("the reconciled apply did not report itself as already applied")
	case out.RollbackID != applied.RollbackID:
		t.Errorf("reconciliation lost the rollback copy: %q", out.RollbackID)
	case readBack(t, f.file) != proposed:
		t.Errorf("the file is %q", readBack(t, f.file))
	}
	if again, err := os.Stat(f.file); err != nil || !again.ModTime().Equal(stat.ModTime()) {
		t.Error("reconciliation wrote the file again")
	}
}

func TestCleanupChangeStore(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed)
	temp := filepath.Join(f.root, tempPrefix+p.PlanID+tempSuffix)
	writeFile(t, temp, "left behind")
	j := &journalRecord{Version: storeVersion, RequestID: "req_left", Op: proto.OpApplyFileChange,
		PlanID: p.PlanID, State: journalIntent, TempPath: temp, At: time.Now().UTC()}
	if err := f.x.changes.saveJournal(j); err != nil {
		t.Fatal(err)
	}
	// An expired plan and its staged content go too.
	rec, err := f.x.changes.loadPlan(p.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Plan.ExpiresAt = time.Now().Add(-time.Hour)
	if err := f.x.changes.savePlan(rec); err != nil {
		t.Fatal(err)
	}
	if err := CleanupChangeStore(f.store, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); err == nil {
		t.Error("startup cleanup left the temporary file")
	}
	if _, err := os.Stat(f.x.changes.contentPath(p.PlanID)); err == nil {
		t.Error("startup cleanup left the expired plan's content")
	}
	if got := readBack(t, f.file); got != original {
		t.Errorf("cleanup touched the target: %q", got)
	}
}

func TestChangeDenyAndHardDenyApplyToChanges(t *testing.T) {
	f := newChangeFixture(t, nil)
	script := filepath.Join(f.root, "fix.ps1")
	writeFile(t, script, "Write-Host\n")
	key := filepath.Join(f.root, "id_rsa")
	writeFile(t, key, "PRIVATE KEY\n")
	for path, code := range map[string]string{
		script: proto.ErrChangeDenied, // an executable script, inside the grant's scope
		key:    proto.ErrHardDenied,   // the read deny list still wins first
	} {
		resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{Path: path, Content: "x\n"})
		wantError(t, resp, code)
	}
	if got := readBack(t, script); got != "Write-Host\n" {
		t.Errorf("a denied change wrote: %q", got)
	}
}

func TestPrepareValidatesTheProposedContent(t *testing.T) {
	f := newChangeFixture(t, nil)
	big := strings.Repeat("a", proto.MaxChangeBytes+1)
	for name, tc := range map[string]struct {
		args proto.PrepareFileChangeArgs
		code string
	}{
		"empty":        {proto.PrepareFileChangeArgs{Path: f.file}, proto.ErrBadRequest},
		"both":         {proto.PrepareFileChangeArgs{Path: f.file, Content: "a", ContentBase64: "YQ=="}, proto.ErrBadRequest},
		"bad base64":   {proto.PrepareFileChangeArgs{Path: f.file, Mode: proto.ChangeModeBinary, ContentBase64: "not base64!"}, proto.ErrBadRequest},
		"bad mode":     {proto.PrepareFileChangeArgs{Path: f.file, Mode: "patch", Content: "a"}, proto.ErrBadRequest},
		"binary bytes": {proto.PrepareFileChangeArgs{Path: f.file, Content: "a\x00b"}, proto.ErrBadRequest},
		"too large":    {proto.PrepareFileChangeArgs{Path: f.file, Content: big}, proto.ErrTooLarge},
		"identical":    {proto.PrepareFileChangeArgs{Path: f.file, Content: original}, proto.ErrBadRequest},
		"directory":    {proto.PrepareFileChangeArgs{Path: f.root, Content: "a"}, proto.ErrNotRegular},
		"missing":      {proto.PrepareFileChangeArgs{Path: filepath.Join(f.root, "absent.conf"), Content: "a"}, proto.ErrNotFound},
		"outside":      {proto.PrepareFileChangeArgs{Path: filepath.Join(filepath.Dir(f.root), "elsewhere.conf"), Content: "a"}, proto.ErrNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, f.call(t, proto.OpPrepareFileChange, tc.args), tc.code)
		})
	}
}

func TestBinaryChangesRoundTripWithoutADiff(t *testing.T) {
	f := newChangeFixture(t, nil)
	content := []byte{0x00, 0x01, 0x02, 0xff}
	resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{
		Path: f.file, Mode: proto.ChangeModeBinary, ContentBase64: "AAEC/w=="})
	p := result[proto.PrepareFileChangeResult](t, resp)
	if !p.Binary || p.Diff != "" {
		t.Errorf("binary plan carries a diff: %+v", p)
	}
	result[proto.ApplyFileChangeResult](t, f.apply(t, p))
	if got := readBack(t, f.file); got != string(content) {
		t.Errorf("binary content round trip: %q", got)
	}
}

func TestGrantAndStoreCeilings(t *testing.T) {
	t.Run("operations per grant", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		var last *proto.Response
		for i := 0; i <= proto.MaxChangeOpsPerGrant; i++ {
			last = f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{
				Path: f.file, Content: proposed + itoa(i)})
		}
		wantError(t, last, proto.ErrQuota)
	})
	t.Run("store quota", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		old := changeStoreQuota
		changeStoreQuota = 64
		t.Cleanup(func() { changeStoreQuota = old })
		wantError(t, f.call(t, proto.OpPrepareFileChange,
			proto.PrepareFileChangeArgs{Path: f.file, Content: strings.Repeat("x", 128)}), proto.ErrQuota)
	})
}

func TestRollbackRetentionAndGrantEnd(t *testing.T) {
	t.Run("capped at the grant's expiry", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		f.cap.ExpiresAt = time.Now().Add(5 * time.Minute).UTC() // sooner than the 24h retention
		p := f.prepare(t, proposed)
		applied := result[proto.ApplyFileChangeResult](t, f.apply(t, p))
		if applied.RollbackTill.After(f.cap.ExpiresAt) {
			t.Errorf("rollback retention %s outlives the grant's expiry %s", applied.RollbackTill, f.cap.ExpiresAt)
		}
	})
	t.Run("refused once the retention window has passed", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		p := f.prepare(t, proposed)
		applied := result[proto.ApplyFileChangeResult](t, f.apply(t, p))
		// Age the rollback copy past its retention window.
		rec, err := f.x.changes.loadPlan(p.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		rec.RollbackUntil = time.Now().Add(-time.Minute)
		if err := f.x.changes.savePlan(rec); err != nil {
			t.Fatal(err)
		}
		wantError(t, f.call(t, proto.OpRollbackFileChange,
			proto.RollbackFileChangeArgs{PlanID: p.PlanID, RollbackID: applied.RollbackID}), proto.ErrStalePlan)
		if got := readBack(t, f.file); got != proposed {
			t.Errorf("an expired rollback still wrote: %q", got)
		}
	})
	t.Run("an expired rollback copy is purged", func(t *testing.T) {
		f := newChangeFixture(t, nil)
		p := f.prepare(t, proposed)
		applied := result[proto.ApplyFileChangeResult](t, f.apply(t, p))
		rec, err := f.x.changes.loadPlan(p.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		rec.Plan.ExpiresAt = time.Now().Add(-time.Hour)
		rec.RollbackUntil = time.Now().Add(-time.Hour)
		if err := f.x.changes.savePlan(rec); err != nil {
			t.Fatal(err)
		}
		f.x.changes.purge(time.Now())
		if _, err := os.Stat(f.x.changes.rollbackPath(applied.RollbackID)); err == nil {
			t.Error("purge kept a rollback copy past its retention")
		}
	})
}

// pendingApprover stands in for the Windows consent UI's review: ReviewChange
// returns at once, as the hub's does, and the test answers each review when it
// chooses, the way a person at the machine would.
type pendingApprover struct {
	mu   sync.Mutex
	err  error // when set, a review cannot be started
	seen []proto.ConsentRequest
	ctxs []context.Context
	outs []chan proto.ConsentDecision
}

func (a *pendingApprover) ReviewChange(ctx context.Context, r proto.ConsentRequest) (<-chan proto.ConsentDecision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, a.err
	}
	out := make(chan proto.ConsentDecision, 1)
	a.seen, a.ctxs, a.outs = append(a.seen, r), append(a.ctxs, ctx), append(a.outs, out)
	return out, nil
}

// last is the most recent review and the context bounding it.
func (a *pendingApprover) last(t *testing.T) (proto.ConsentRequest, context.Context, chan proto.ConsentDecision) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.seen) == 0 {
		t.Fatal("no review was started")
	}
	n := len(a.seen) - 1
	return a.seen[n], a.ctxs[n], a.outs[n]
}

// answer gives the most recent review its one decision and closes it.
func (a *pendingApprover) answer(t *testing.T, d proto.ConsentDecision) {
	t.Helper()
	_, _, out := a.last(t)
	out <- d
	close(out)
}

// watchReviews reports each plan whose review outcome the store has recorded.
func (f *changeFixture) watchReviews() <-chan string {
	ch := make(chan string, 8)
	f.x.changes.reviewed = func(planID string) { ch <- planID }
	return ch
}

func waitReview(t *testing.T, reviewed <-chan string, planID string) {
	t.Helper()
	select {
	case got := <-reviewed:
		if got != planID {
			t.Fatalf("recorded a review for %s, want %s", got, planID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the review outcome was never recorded")
	}
}

func TestLocalReviewDoesNotHoldThePrepare(t *testing.T) {
	a := &pendingApprover{}
	f := newChangeFixture(t, a)
	reviewed := f.watchReviews()

	// Prepare returns with nobody having answered yet.
	p := f.prepare(t, proposed)
	if p.Approved || p.Review != reviewAwaiting {
		t.Fatalf("prepare returned approved=%t review=%q; want a review awaiting the person at the machine", p.Approved, p.Review)
	}
	if readBack(t, f.file) != original {
		t.Fatal("prepare touched the target")
	}
	seen, ctx, _ := a.last(t)
	if seen.PlanDigest != p.PlanDigest || seen.AccessID != f.cap.AccessID || seen.Technician != f.cap.Technician || seen.Purpose != "ticket 42" {
		t.Errorf("the review was shown %+v", seen)
	}
	var shown proto.ChangePlan
	if err := json.Unmarshal(seen.Plan, &shown); err != nil || !strings.Contains(shown.Diff, "+level=debug") {
		t.Errorf("the review was shown %v %q", err, shown.Diff)
	}
	// The review outlives the request that prepared it and ends with the plan.
	if ctx.Err() != nil {
		t.Fatal("the review ended with the prepare request")
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(p.ExpiresAt) {
		t.Errorf("the review is bounded by %v (%t), want the plan's expiry %v", deadline, ok, p.ExpiresAt)
	}

	// Until the person at the machine answers, apply is refused and nothing is written.
	wantError(t, f.apply(t, p), proto.ErrConsentRequired)
	if readBack(t, f.file) != original {
		t.Fatal("an unreviewed plan was applied")
	}

	a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, Approver: `ACME\sam`, PlanDigest: p.PlanDigest})
	waitReview(t, reviewed, p.PlanID)
	resp := f.apply(t, p)
	result[proto.ApplyFileChangeResult](t, resp)
	if readBack(t, f.file) != proposed {
		t.Fatal("the approved change was not applied")
	}
	if resp.Meta.Change == nil || resp.Meta.Change.Approver != `ACME\sam` {
		t.Errorf("the apply's audit metadata is %+v; want it to name the approver", resp.Meta.Change)
	}
	if ctx.Err() == nil {
		t.Error("the review's context outlived its answer")
	}
}

func TestLocalReviewWithoutApprovalWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(t *testing.T, a *pendingApprover, p proto.PrepareFileChangeResult)
	}{
		{"denied, even unelevated", func(t *testing.T, a *pendingApprover, p proto.PrepareFileChangeResult) {
			a.answer(t, proto.ConsentDecision{State: proto.ConsentDenied, Approver: `ACME\sam`, PlanDigest: p.PlanDigest})
		}},
		{"ended unanswered", func(t *testing.T, a *pendingApprover, _ proto.PrepareFileChangeResult) {
			_, _, out := a.last(t)
			close(out)
		}},
		{"signs another plan", func(t *testing.T, a *pendingApprover, _ proto.PrepareFileChangeResult) {
			a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, Approver: `ACME\sam`, PlanDigest: strings.Repeat("1", 64)})
		}},
		{"names no approver", func(t *testing.T, a *pendingApprover, p proto.PrepareFileChangeResult) {
			a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, PlanDigest: p.PlanDigest})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &pendingApprover{}
			f := newChangeFixture(t, a)
			reviewed := f.watchReviews()
			p := f.prepare(t, proposed)
			tc.answer(t, a, p)
			waitReview(t, reviewed, p.PlanID)
			wantError(t, f.apply(t, p), proto.ErrConsentRequired)
			if readBack(t, f.file) != original {
				t.Fatal("a plan that was not approved was applied")
			}
		})
	}
}

func TestLocalReviewThatCannotStartStagesNothing(t *testing.T) {
	f := newChangeFixture(t, &pendingApprover{err: errors.New("no local consent window is watching this grant")})
	resp := f.call(t, proto.OpPrepareFileChange, proto.PrepareFileChangeArgs{Path: f.file, Content: proposed})
	wantError(t, resp, proto.ErrConsentRequired)
	if !strings.Contains(resp.Error.Message, "no local consent window") {
		t.Errorf("the refusal does not say why: %q", resp.Error.Message)
	}
	entries, err := os.ReadDir(filepath.Join(f.store, plansDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("a plan nobody could review was left staged: %s", e.Name())
	}
}

// TestLocalApprovalRacingApplies answers a review while applies are in
// flight: each apply is refused until the approval is recorded, exactly one
// then succeeds, and the race detector sees the store's locking.
func TestLocalApprovalRacingApplies(t *testing.T) {
	a := &pendingApprover{}
	f := newChangeFixture(t, a)
	reviewed := f.watchReviews()
	p := f.prepare(t, proposed)

	var (
		mu      sync.Mutex
		ok      int
		refused = map[string]int{}
		wg      sync.WaitGroup
	)
	deadline := time.Now().Add(3 * time.Second)
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; time.Now().Before(deadline); n++ {
				resp := f.callID(t, proto.OpApplyFileChange, proto.ApplyFileChangeArgs{PlanID: p.PlanID, PlanDigest: p.PlanDigest},
					"req_race_"+itoa(i)+"_"+itoa(n))
				mu.Lock()
				if resp.Error == nil {
					ok++
				} else {
					refused[resp.Error.Code]++
				}
				done := ok > 0
				mu.Unlock()
				if done {
					return
				}
			}
		}()
	}
	a.answer(t, proto.ConsentDecision{State: proto.ConsentApproved, Approver: `ACME\sam`, PlanDigest: p.PlanDigest})
	waitReview(t, reviewed, p.PlanID)
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d applies succeeded (refusals %v); want exactly one", ok, refused)
	}
	for code := range refused {
		switch code {
		case proto.ErrConsentRequired, proto.ErrConflict, proto.ErrStalePlan:
		default:
			t.Errorf("an apply racing the approval failed with %s", code)
		}
	}
	if readBack(t, f.file) != proposed {
		t.Fatal("the approved change is not in place")
	}
}

func TestPlanStagedWithoutReviewCannotBeAppliedOnceReviewIsRequired(t *testing.T) {
	f := newChangeFixture(t, nil)
	p := f.prepare(t, proposed) // staged without a local review
	f.x = New(Options{ChangeDir: f.store, PlanApprover: &pendingApprover{}})
	wantError(t, f.apply(t, p), proto.ErrConsentRequired)
}

func TestServiceOpsAreGatedByPolicyAndTheDenyList(t *testing.T) {
	f := newChangeFixture(t, nil)
	// Nothing is allowed until the client's policy names the service.
	wantError(t, f.call(t, proto.OpServiceQuery, proto.ServiceQueryArgs{Name: "VendorService"}), proto.ErrNotAllowed)
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "VendorService"}), proto.ErrNotAllowed)
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: `C:\Windows\System32\svc.exe`}), proto.ErrBadRequest)

	f.pol.ServiceAllow = []string{"VendorService", "keyhole-agent"}
	// The compiled-in deny list wins over the policy for a restart.
	wantError(t, f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "keyhole-agent"}), proto.ErrChangeDenied)
	// An allowed service reaches the platform, which answers per OS.
	resp := f.call(t, proto.OpServiceRestart, proto.ServiceRestartArgs{Name: "VendorService"})
	if resp.OK {
		t.Skip("this machine really has a VendorService")
	}
	switch resp.Error.Code {
	case proto.ErrUnsupported, proto.ErrNotFound, proto.ErrIO, proto.ErrTimeout:
	default:
		t.Errorf("restart of an allowed service: %+v", resp.Error)
	}
}

func TestUnifiedDiffIsBoundedAndReadable(t *testing.T) {
	before := strings.Repeat("same\n", 10) + "old\n" + strings.Repeat("same\n", 10)
	after := strings.Repeat("same\n", 10) + "new\n" + strings.Repeat("same\n", 10)
	diff, lines, truncated := unifiedDiff(before, after, "/etc/app.conf")
	switch {
	case truncated:
		t.Error("a one-line change was truncated")
	case !strings.Contains(diff, "@@ -8,7 +8,7 @@"):
		t.Errorf("hunk header missing:\n%s", diff)
	case !strings.Contains(diff, "-old") || !strings.Contains(diff, "+new"):
		t.Errorf("change missing:\n%s", diff)
	case strings.Count(diff, "\n") != lines:
		t.Errorf("reported %d lines for:\n%s", lines, diff)
	case lines > 12:
		t.Errorf("a one-line change produced %d diff lines:\n%s", lines, diff)
	}

	big := ""
	for i := range 5000 {
		big += "line " + itoa(i) + "\n"
	}
	diff, lines, truncated = unifiedDiff(big, strings.ReplaceAll(big, "line ", "row "), "/etc/app.conf")
	if !truncated || lines > proto.MaxChangeDiffLines+2 || len(diff) > proto.MaxChangeDiffBytes+256 {
		t.Errorf("a whole-file rewrite produced %d lines and %d bytes, truncated=%v", lines, len(diff), truncated)
	}
}
