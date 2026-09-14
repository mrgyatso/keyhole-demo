package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

var gateChangeOps = []string{proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange}

// Under technician approval a prepare is a dry run that prompts nobody, and
// the relay keeps the plan, diff included, for the technician's change card.
func TestGatePrepareRecordsThePlanForTheCompanion(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{"device": gateDevice, "access_id": a.ID,
		"path": gateFile, "content": `{"retries": 5}`, "reason": "ticket 42"})
	if isErr {
		t.Fatalf("prepare: %s", text)
	}
	planID, digest := planFrom(t, text)
	for _, want := range []string{"Nothing has been written", "dry run", "apply_file_change", "Keyhole companion", boundaryTag} {
		if !strings.Contains(text, want) {
			t.Errorf("prepare says:\n%s\nwant it to mention %q", text, want)
		}
	}
	if strings.Contains(text, proto.ErrConsentRequired) {
		t.Errorf("prepare sends the model to the person at the machine:\n%s", text)
	}
	rec, err := f.st.ChangePlan(context.Background(), planID)
	if err != nil {
		t.Fatalf("the plan was not recorded: %v", err)
	}
	var plan proto.ChangePlan
	if err := json.Unmarshal(rec.Plan, &plan); err != nil {
		t.Fatalf("the recorded plan is not a ChangePlan: %v", err)
	}
	switch {
	case rec.AccessID != a.ID || rec.Client != "acme" || rec.Device != gateDevice || rec.Technician != "tech_alice" || rec.Digest != digest:
		t.Errorf("plan record %+v", rec)
	case !rec.PreparedAt.Equal(f.clock.now()) || plan.ExpiresAt.IsZero() || !rec.ExpiresAt.Equal(plan.ExpiresAt):
		t.Errorf("plan record prepared %s, expires %s; the plan expires %s", rec.PreparedAt, rec.ExpiresAt, plan.ExpiresAt)
	case plan.PlanID != planID || plan.PlanDigest != digest || !strings.Contains(plan.Diff, `{"retries": 5}`) || plan.Reason != "ticket 42":
		t.Errorf("the recorded plan lacks the diff or the reason: %+v", plan)
	}
	if got := f.access(t, a.ID).PlanDigest; got != digest {
		t.Errorf("the grant records plan digest %q, want %q", got, digest)
	}
}

// The central property of the change gate: nothing reaches the endpoint
// before the technician approves. apply_file_change stores an approval and
// answers with its companion link; the machine sees only the prepare, and the
// file is untouched.
func TestGateSubmitContactsNoMachine(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, `{"retries": 5}`)
	before := len(f.ep.requests(""))

	sub := f.apply(t, cs, a, planID, digest)
	if got := f.ep.requests(""); len(got) != before {
		t.Fatalf("submitting a change reached the machine: %+v", got[before:])
	}
	if got := f.ep.file(); got != gateOriginal {
		t.Fatalf("the file was written before approval: %q", got)
	}
	row := f.row(t, sub.ApprovalID)
	now := f.clock.now()
	switch {
	case sub.State != model.ChangeAwaiting || row.State != model.ChangeAwaiting:
		t.Errorf("submission %+v, stored %s", sub, row.State)
	case sub.Link != gateCompanion+"/c/"+row.ID:
		t.Errorf("link %q", sub.Link)
	case !sub.ExpiresAt.Equal(row.ExpiresAt) || !row.ExpiresAt.Equal(now.Add(model.ChangeApprovalWindow)):
		t.Errorf("expires %s (stored %s), want the approval window from now", sub.ExpiresAt, row.ExpiresAt)
	case row.Op != proto.OpApplyFileChange || row.Technician != "tech_alice" || row.Client != "acme" || row.Device != gateDevice ||
		row.AccessID != a.ID || row.GrantID != a.GrantID || row.Session != "idp_gate_alice" || row.PlanID != planID || row.PlanDigest != digest:
		t.Errorf("stored approval %+v", row)
	case len(row.Nonce) < 22 || !strings.HasPrefix(row.RequestID, model.PrefixRequest+"_"):
		t.Errorf("nonce %q (want at least 128 bits), request ID %q", row.Nonce, row.RequestID)
	}
	for _, want := range []string{"Nothing has been written", "Keyhole companion", "change_status"} {
		if !strings.Contains(sub.Message, want) {
			t.Errorf("the submission says %q; want it to mention %q", sub.Message, want)
		}
	}

	var tool *audit.Entry
	for _, e := range f.entries(t, "acme") {
		if e.Kind == audit.KindTool && e.Tool == proto.OpApplyFileChange {
			tool = &e
		}
	}
	if tool == nil || tool.Result != audit.ResultOK || tool.RequestID != row.ID || tool.Tech != "tech_alice" {
		t.Errorf("the submit's tool-call entry: %+v", tool)
	}
	e, ok := f.consent(t, row.ID, model.ChangeAwaiting)
	if !ok {
		t.Fatal("the new approval was not audited")
	}
	var args changeAudit
	if err := json.Unmarshal(e.Args, &args); err != nil || args.Source != "technician" || args.Op != proto.OpApplyFileChange ||
		args.PlanID != planID || args.PlanDigest != digest || e.Tech != "tech_alice" || e.SessionID != "idp_gate_alice" {
		t.Errorf("change.awaiting_approval entry %+v, args %s", e, e.Args)
	}
}

// An approval is the card's deadline and the validity the endpoint enforces,
// so it lapses with its plan or its grant when either ends sooner.
func TestGateApprovalNeverOutlivesThePlanOrTheGrant(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	short := f.grant(t, "tech_alice", "idp_gate_alice", 10*time.Minute, gateChangeOps...)
	planID, digest := f.prepare(t, cs, short, "a")
	if sub := f.apply(t, cs, short, planID, digest); !sub.ExpiresAt.Equal(short.ExpiresAt) {
		t.Errorf("under a grant ending at %s the approval lapses at %s", short.ExpiresAt, sub.ExpiresAt)
	}
	// A rollback is not bound by its plan's expiry, only by the grant's.
	if sub := f.submit(t, cs, proto.OpRollbackFileChange, map[string]any{"device": gateDevice, "access_id": short.ID,
		"plan_id": planID}); !sub.ExpiresAt.Equal(short.ExpiresAt) {
		t.Errorf("under a grant ending at %s the rollback's approval lapses at %s", short.ExpiresAt, sub.ExpiresAt)
	}
	long := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest = f.prepare(t, cs, long, "b")
	f.advance(20 * time.Minute) // the plan has ten minutes left, less than the approval window
	rec, err := f.st.ChangePlan(context.Background(), planID)
	if err != nil {
		t.Fatal(err)
	}
	if sub := f.apply(t, cs, long, planID, digest); !sub.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Errorf("for a plan expiring at %s the approval lapses at %s", rec.ExpiresAt, sub.ExpiresAt)
	}
}

// One plan gets one card: submitting it again while it waits, or while it is
// being released, answers with the same approval.
func TestGateDuplicateSubmitReturnsThePendingApproval(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	first := f.apply(t, cs, a, planID, digest)
	if again := f.apply(t, cs, a, planID, digest); again.ApprovalID != first.ApprovalID || again.State != model.ChangeAwaiting {
		t.Fatalf("second submit %+v, want %s", again, first.ApprovalID)
	}
	f.ep.offline(t)
	if got := f.approve(t, first.ApprovalID, "cred-alice"); got.State != model.ChangeApproved {
		t.Fatalf("approved while the machine is offline: %s", got.State)
	}
	if again := f.apply(t, cs, a, planID, digest); again.ApprovalID != first.ApprovalID || again.State != model.ChangeApproved {
		t.Fatalf("submit during the release %+v, want %s approved", again, first.ApprovalID)
	}
	if list, _ := f.st.ChangeApprovals(context.Background(), "tech_alice", time.Time{}); len(list) != 1 {
		t.Fatalf("%d approvals for one plan", len(list))
	}
	n := 0
	for _, e := range f.entries(t, "acme") {
		if e.Tool == "change."+model.ChangeAwaiting {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d change.awaiting_approval entries for one plan", n)
	}
}

// A submit that does not match the relay's copy of the plan, or the caller's
// own grant, is refused and audited, stores nothing, and reaches no machine.
func TestGateRefusesSubmitsThatDoNotMatchThePlan(t *testing.T) {
	f := newGateFixture(t)
	alice := f.connect(t, gateBearerAlice)
	bob := f.connect(t, gateBearerBob)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	other := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	readOnly := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, proto.OpReadFile)
	bobs := f.grant(t, "tech_bob", "idp_gate_bob", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, alice, a, "a")
	args := func(access, plan, digest string) map[string]any {
		return map[string]any{"device": gateDevice, "access_id": access, "plan_id": plan, "plan_digest": digest}
	}
	refuse := func(name string, cs *mcp.ClientSession, args map[string]any, code string) {
		t.Helper()
		text, isErr := call(t, cs, proto.OpApplyFileChange, args)
		if !isErr || !strings.HasPrefix(text, code+":") {
			t.Errorf("%s: %q, error %v; want %s", name, text, isErr, code)
		}
		es := f.entries(t, "acme")
		if e := es[len(es)-1]; e.Kind != audit.KindTool || e.Tool != proto.OpApplyFileChange || e.Result != audit.ResultDenied {
			t.Errorf("%s was audited as %+v", name, e)
		}
	}
	refuse("a digest the plan does not have", alice, args(a.ID, planID, "digest-other"), proto.ErrStalePlan)
	refuse("no digest", alice, args(a.ID, planID, ""), proto.ErrBadRequest)
	refuse("another grant of the same technician", alice, args(other.ID, planID, digest), proto.ErrGrantInvalid)
	refuse("a grant without apply_file_change", alice, args(readOnly.ID, planID, digest), proto.ErrGrantInvalid)
	refuse("a plan nobody prepared", alice, args(a.ID, "plan_nothing", digest), proto.ErrGrantInvalid)
	refuse("another technician's plan", bob, args(bobs.ID, planID, digest), proto.ErrGrantInvalid)
	refuse("another technician's grant", bob, args(a.ID, planID, digest), proto.ErrGrantInvalid)
	f.advance(proto.ChangePlanTTL + time.Minute)
	refuse("an expired plan", alice, args(a.ID, planID, digest), proto.ErrStalePlan)

	for _, tech := range []string{"tech_alice", "tech_bob"} {
		if list, _ := f.st.ChangeApprovals(context.Background(), tech, time.Time{}); len(list) != 0 {
			t.Errorf("refused submits stored approvals for %s: %+v", tech, list)
		}
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 0 {
		t.Errorf("refused submits reached the machine %d times", n)
	}
}

// ApproveChange takes only an approval that signs exactly the stored row, by a
// live passkey of the row's technician, while the row still waits. Anything
// else leaves the row as it was and reaches no machine.
func TestGateApproveChangeRefusesWhatItDoesNotBind(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	row := f.row(t, f.apply(t, cs, a, planID, digest).ApprovalID)
	if err := f.st.RevokePasskey(ctx, "cred-alice-old", f.clock.now()); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		change func(*proto.TechnicianApproval)
		want   error
	}{
		"another nonce":            {func(a *proto.TechnicianApproval) { a.Nonce = "guessed" }, model.ErrInvalid},
		"another expiry":           {func(a *proto.TechnicianApproval) { a.ExpiresAt = a.ExpiresAt.Add(time.Hour) }, model.ErrInvalid},
		"another plan digest":      {func(a *proto.TechnicianApproval) { a.PlanDigest = "digest-other" }, model.ErrInvalid},
		"another grant":            {func(a *proto.TechnicianApproval) { a.GrantID = "grt_other" }, model.ErrInvalid},
		"an unlock's approval":     {func(a *proto.TechnicianApproval) { a.Kind = proto.ApprovalUnlock }, model.ErrInvalid},
		"unsigned":                 {func(a *proto.TechnicianApproval) { a.Credential, a.ApprovedAt = "", time.Time{} }, model.ErrInvalid},
		"another technician's key": {func(a *proto.TechnicianApproval) { a.Credential = "cred-bob" }, model.ErrInvalid},
		"a passkey nobody has":     {func(a *proto.TechnicianApproval) { a.Credential = "cred-nobody" }, model.ErrInvalid},
		"a revoked passkey":        {func(a *proto.TechnicianApproval) { a.Credential = "cred-alice-old" }, model.ErrRevoked},
		"another technician":       {func(a *proto.TechnicianApproval) { a.Technician, a.Credential = "tech_bob", "cred-bob" }, model.ErrNotFound},
	} {
		approval := f.sign(row, "cred-alice")
		c.change(&approval)
		if _, err := f.g.ApproveChange(ctx, row.ID, approval); !errors.Is(err, c.want) {
			t.Errorf("%s: ApproveChange = %v, want %v", name, err, c.want)
		}
	}
	if got := f.row(t, row.ID); got.State != model.ChangeAwaiting || got.Credential != "" || got.DecidedAt != nil {
		t.Fatalf("a refused approval changed the row: %+v", got)
	}

	// A row that no longer waits cannot be approved.
	if _, err := f.g.DenyChange(ctx, row.ID, "tech_alice", "cred-alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.ApproveChange(ctx, row.ID, f.sign(row, "cred-alice")); !errors.Is(err, model.ErrConflict) {
		t.Errorf("approving a denied change: %v", err)
	}
	// Nor one that has lapsed, even before the reconcile loop notices.
	planID, digest = f.prepare(t, cs, a, "b")
	late := f.row(t, f.apply(t, cs, a, planID, digest).ApprovalID)
	f.advance(model.ChangeApprovalWindow)
	if _, err := f.g.ApproveChange(ctx, late.ID, f.sign(late, "cred-alice")); !errors.Is(err, model.ErrExpired) {
		t.Errorf("approving a lapsed change: %v", err)
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 0 {
		t.Fatalf("an approval the gate refused reached the machine %d times", n)
	}
}

// Approving releases the change through the ordinary device-call path: the
// endpoint gets the signed approval of exactly this plan and grant, under the
// approval's own request ID, and the outcome is recorded with its result.
func TestGateApprovalReleasesTheChangeWithItsApproval(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, `{"retries": 5}`)
	pending := f.row(t, f.apply(t, cs, a, planID, digest).ApprovalID)
	signed := f.sign(pending, "cred-alice")

	got, err := f.g.ApproveChange(ctx, pending.ID, signed)
	if err != nil {
		t.Fatal(err)
	}
	var result proto.ApplyFileChangeResult
	if err := json.Unmarshal(got.Result, &result); err != nil {
		t.Fatalf("the outcome has no result: %+v", got)
	}
	switch {
	case got.State != model.ChangeApplied || got.CompletedAt == nil || got.ErrorCode != "":
		t.Fatalf("after approval: %+v", got)
	case got.DecidedAt == nil || !got.DecidedAt.Equal(signed.ApprovedAt) || got.Credential != "cred-alice":
		t.Errorf("decided %v by %q, want %s by cred-alice", got.DecidedAt, got.Credential, signed.ApprovedAt)
	case result.PlanID != planID || result.RollbackID == "":
		t.Errorf("result %+v", result)
	}
	var assertion proto.PasskeyAssertion
	if err := json.Unmarshal(f.row(t, got.ID).Assertion, &assertion); err != nil || assertion.CredentialID != "cred-alice" {
		t.Errorf("the approving assertion was not kept: %+v, %v", assertion, err)
	}

	reqs := f.ep.requests(proto.OpApplyFileChange)
	if len(reqs) != 1 {
		t.Fatalf("the machine got %d applies", len(reqs))
	}
	req := reqs[0]
	var args proto.ApplyFileChangeArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		t.Fatal(err)
	}
	switch {
	case req.ID != pending.RequestID:
		t.Errorf("released as request %s, want the approval's %s", req.ID, pending.RequestID)
	case req.Capability == nil || req.Capability.GrantID != a.GrantID || req.Capability.AccessID != a.ID:
		t.Errorf("capability %+v", req.Capability)
	case req.Caller.Tech != "tech_alice" || req.Caller.Session != "idp_gate_alice":
		t.Errorf("released as %+v", req.Caller)
	case args.PlanID != planID || args.PlanDigest != digest || args.Approval == nil:
		t.Fatalf("args %+v", args)
	case !args.Approval.SameSigned(pending.Approval()) || args.Approval.Credential != "cred-alice" ||
		!args.Approval.ApprovedAt.Equal(signed.ApprovedAt) || args.Approval.Assertion == nil:
		t.Errorf("the release carries approval %+v", args.Approval)
	}
	if got := f.ep.file(); got != `{"retries": 5}` {
		t.Errorf("file %q after the release", got)
	}
	if d := f.access(t, a.ID).PlanDigest; d != "" {
		t.Errorf("the grant still carries the applied plan %q", d)
	}

	approved, ok := f.consent(t, pending.ID, model.ChangeApproved)
	if !ok || !strings.Contains(string(approved.Args), `"credential":"cred-alice"`) {
		t.Errorf("change.approved entry %+v", approved)
	}
	if e, ok := f.consent(t, pending.ID, model.ChangeApplied); !ok || e.Result != audit.ResultOK {
		t.Errorf("change.applied entry %+v", e)
	}
	rel := f.releases(t, pending.RequestID)
	if len(rel) != 1 {
		t.Fatalf("%d release entries", len(rel))
	}
	var change proto.ChangeMeta
	if err := json.Unmarshal(rel[0].Change, &change); err != nil || change.ApprovalID != pending.ID || rel[0].Tool != proto.OpApplyFileChange ||
		rel[0].Result != audit.ResultOK || rel[0].Tech != "tech_alice" || rel[0].SessionID != "idp_gate_alice" || rel[0].SHA256 == "" {
		t.Errorf("release entry %+v", rel[0])
	}
	for _, e := range f.entries(t, "acme") {
		if raw, _ := json.Marshal(e); strings.Contains(string(raw), "c2lnbmF0dXJl") { // base64 of the assertion's signature
			t.Errorf("an audit entry records the passkey assertion: %s", raw)
		}
	}
	if v, err := f.log.Verify(ctx, "acme"); err != nil || !v.OK {
		t.Fatalf("audit chain: %+v %v", v, err)
	}
	if st := gateStatus(t, cs, pending.ID); st.State != model.ChangeApplied || !strings.Contains(string(st.Result), result.RollbackID) {
		t.Errorf("change_status %+v", st)
	}
}

// A refusal by the endpoint on the first release is final: nothing was
// written, and the outcome says why.
func TestGateRecordsTheMachinesRefusal(t *testing.T) {
	for name, c := range map[string]struct {
		tweak func(*gateEndpoint)
		code  string
	}{
		"the file changed after review":    {func(ep *gateEndpoint) { ep.files[gateFile] = "changed by someone else" }, proto.ErrStalePlan},
		"the machine refuses the approval": {func(ep *gateEndpoint) { ep.refuse = proto.ErrApprovalRequired }, proto.ErrApprovalRequired},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGateFixture(t)
			cs := f.connect(t, gateBearerAlice)
			a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
			planID, digest := f.prepare(t, cs, a, "a")
			sub := f.apply(t, cs, a, planID, digest)
			f.ep.set(c.tweak)
			before, writes := f.ep.file(), f.ep.writeCount()
			got := f.approve(t, sub.ApprovalID, "cred-alice")
			if got.State != model.ChangeRefused || got.ErrorCode != c.code || got.Reason == "" || got.CompletedAt == nil {
				t.Fatalf("after a refusal: %+v", got)
			}
			if f.ep.file() != before || f.ep.writeCount() != writes {
				t.Error("a refused change was written")
			}
			if e, ok := f.consent(t, got.ID, model.ChangeRefused); !ok || e.Result != audit.ResultDenied || e.ErrorCode != c.code {
				t.Errorf("change.refused entry %+v", e)
			}
			if st := gateStatus(t, cs, got.ID); st.State != model.ChangeRefused || st.ErrorCode != c.code ||
				!strings.Contains(st.Message, "nothing was written") {
				t.Errorf("change_status %+v", st)
			}
		})
	}
}

// A release that cannot reach the machine leaves the change approved; the
// reconcile loop releases it again, with the same request ID, once it can.
func TestGateRetriesAnUndeliveredReleaseWithTheSameRequestID(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "b")
	sub := f.apply(t, cs, a, planID, digest)
	f.ep.offline(t)

	got := f.approve(t, sub.ApprovalID, "cred-alice")
	if got.State != model.ChangeApproved || got.ErrorCode != proto.ErrDeviceOffline || got.CompletedAt != nil {
		t.Fatalf("an undelivered release: %+v", got)
	}
	if st := gateStatus(t, cs, got.ID); st.State != model.ChangeApproved || !strings.Contains(st.Message, "tries again") {
		t.Errorf("change_status while undelivered: %+v", st)
	}
	f.advance(time.Minute)
	f.g.reconcileChanges(ctx) // still offline
	if row := f.row(t, got.ID); row.State != model.ChangeApproved {
		t.Fatalf("a retry that did not get through: %+v", row)
	}
	f.ep.online(t)
	f.g.reconcileChanges(ctx)
	if row := f.row(t, got.ID); row.State != model.ChangeApplied || row.ErrorCode != "" || len(row.Result) == 0 {
		t.Fatalf("after the machine came back: %+v", row)
	}
	reqs := f.ep.requests(proto.OpApplyFileChange)
	if len(reqs) != 1 || reqs[0].ID != got.RequestID {
		t.Fatalf("the machine got %+v, want one apply with request ID %s", reqs, got.RequestID)
	}
	rel := f.releases(t, got.RequestID)
	if len(rel) != 3 || rel[0].Result != audit.ResultError || rel[1].Result != audit.ResultError || rel[2].Result != audit.ResultOK {
		t.Errorf("every attempt is audited under the one request ID: %+v", rel)
	}
	if f.ep.file() != "b" {
		t.Errorf("file %q", f.ep.file())
	}
}

// A release whose answer is lost is released again with the same request ID,
// and the endpoint's journal answers it with the first result instead of
// writing a second time.
func TestGateReplaysALostAnswerInsteadOfWritingTwice(t *testing.T) {
	f := newGateFixture(t, func(cfg *Config) { cfg.RPCTimeout = 500 * time.Millisecond })
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "b")
	sub := f.apply(t, cs, a, planID, digest)
	f.ep.set(func(ep *gateEndpoint) { ep.drop = true })

	got := f.approve(t, sub.ApprovalID, "cred-alice")
	if got.State != model.ChangeApproved || got.ErrorCode != proto.ErrDeviceOffline {
		t.Fatalf("a release whose answer was lost: %+v", got)
	}
	f.g.reconcileChanges(ctx)
	row := f.row(t, got.ID)
	if row.State != model.ChangeApplied || len(row.Result) == 0 {
		t.Fatalf("after the retry: %+v", row)
	}
	reqs := f.ep.requests(proto.OpApplyFileChange)
	if len(reqs) != 2 || reqs[0].ID != got.RequestID || reqs[1].ID != got.RequestID {
		t.Fatalf("applies %+v, want two with request ID %s", reqs, got.RequestID)
	}
	if n := f.ep.writeCount(); n != 1 {
		t.Fatalf("the file was written %d times", n)
	}
}

// The relay applies its own deadlines: an approval nobody answered expires,
// and one approved but never delivered fails once the endpoint would refuse
// its approval anyway.
func TestGateExpiresUnansweredAndFailsUndeliveredChanges(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	unanswered := f.apply(t, cs, a, planID, digest)
	planID, digest = f.prepare(t, cs, a, "b")
	undelivered := f.apply(t, cs, a, planID, digest)
	f.ep.offline(t)
	f.approve(t, undelivered.ApprovalID, "cred-alice")

	f.advance(model.ChangeApprovalWindow)
	f.g.reconcileChanges(ctx)
	row := f.row(t, unanswered.ApprovalID)
	if row.State != model.ChangeExpired || row.Reason != model.ReasonUnanswered {
		t.Fatalf("an unanswered approval after its deadline: %+v", row)
	}
	if e, ok := f.consent(t, row.ID, model.ChangeExpired); !ok || e.Result != audit.ResultDenied {
		t.Errorf("change.expired entry %+v", e)
	}
	// The endpoint still accepts the approval within its clock skew, so the
	// relay keeps trying until then.
	if row := f.row(t, undelivered.ApprovalID); row.State != model.ChangeApproved {
		t.Fatalf("an undelivered approval inside the clock skew: %+v", row)
	}
	f.advance(proto.ApprovalClockSkew)
	f.g.reconcileChanges(ctx)
	row = f.row(t, undelivered.ApprovalID)
	if row.State != model.ChangeFailed || row.Reason != proto.ReasonExpired || row.ErrorCode != proto.ErrDeviceOffline || row.CompletedAt == nil {
		t.Fatalf("an undelivered approval after it lapsed: %+v", row)
	}
	if e, ok := f.consent(t, row.ID, model.ChangeFailed); !ok || e.Result != audit.ResultError {
		t.Errorf("change.failed entry %+v", e)
	}
	if _, err := f.g.ApproveChange(ctx, unanswered.ApprovalID, f.sign(f.row(t, unanswered.ApprovalID), "cred-alice")); !errors.Is(err, model.ErrConflict) {
		t.Errorf("approving an expired change: %v", err)
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 0 {
		t.Errorf("the machine got %d applies", n)
	}
}

func TestGateDenyChange(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	sub := f.apply(t, cs, a, planID, digest)

	if _, err := f.g.DenyChange(ctx, sub.ApprovalID, "tech_bob", "cred-bob"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("another technician denied it: %v", err)
	}
	got, err := f.g.DenyChange(ctx, sub.ApprovalID, "tech_alice", "cred-alice")
	if err != nil || got.State != model.ChangeDenied || got.Credential != "cred-alice" || got.DecidedAt == nil || !got.DecidedAt.Equal(f.clock.now()) {
		t.Fatalf("DenyChange = %+v, %v", got, err)
	}
	if _, err := f.g.DenyChange(ctx, sub.ApprovalID, "tech_alice", "cred-alice"); !errors.Is(err, model.ErrConflict) {
		t.Errorf("denying twice: %v", err)
	}
	if _, err := f.g.ApproveChange(ctx, got.ID, f.sign(got, "cred-alice")); !errors.Is(err, model.ErrConflict) {
		t.Errorf("approving a denied change: %v", err)
	}
	if e, ok := f.consent(t, got.ID, model.ChangeDenied); !ok || e.Result != audit.ResultDenied || !strings.Contains(string(e.Args), `"credential":"cred-alice"`) {
		t.Errorf("change.denied entry %+v", e)
	}
	if st := gateStatus(t, cs, got.ID); st.State != model.ChangeDenied {
		t.Errorf("change_status %+v", st)
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 0 {
		t.Errorf("a denied change reached the machine %d times", n)
	}
}

// Rollback checks no review at the machine, so it goes through the gate
// exactly like an apply: submitted, approved on its own, released with an
// approval that names its rollback.
func TestGateRollbackGoesThroughTheGate(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, `{"retries": 5}`)
	applied := f.approve(t, f.apply(t, cs, a, planID, digest).ApprovalID, "cred-alice")
	var res proto.ApplyFileChangeResult
	if err := json.Unmarshal(applied.Result, &res); err != nil || res.RollbackID == "" {
		t.Fatalf("apply result %s", applied.Result)
	}

	before := len(f.ep.requests(""))
	sub := f.submit(t, cs, proto.OpRollbackFileChange, map[string]any{"device": gateDevice, "access_id": a.ID,
		"plan_id": planID, "rollback_id": res.RollbackID})
	if len(f.ep.requests("")) != before || f.ep.file() != `{"retries": 5}` {
		t.Fatal("submitting a rollback reached the machine")
	}
	row := f.row(t, sub.ApprovalID)
	if row.Op != proto.OpRollbackFileChange || row.RollbackID != res.RollbackID || row.PlanDigest != digest || row.State != model.ChangeAwaiting {
		t.Fatalf("rollback approval %+v", row)
	}
	if got := f.approve(t, row.ID, "cred-alice"); got.State != model.ChangeApplied {
		t.Fatalf("after approving the rollback: %+v", got)
	}
	reqs := f.ep.requests(proto.OpRollbackFileChange)
	if len(reqs) != 1 || reqs[0].ID != row.RequestID {
		t.Fatalf("rollbacks %+v", reqs)
	}
	var args proto.RollbackFileChangeArgs
	if err := json.Unmarshal(reqs[0].Args, &args); err != nil || args.Approval == nil ||
		args.Approval.Op != proto.OpRollbackFileChange || args.Approval.RollbackID != res.RollbackID || !args.Approval.SameSigned(row.Approval()) {
		t.Fatalf("rollback args %+v", args)
	}
	if got := f.ep.file(); got != gateOriginal {
		t.Errorf("file %q after the rollback", got)
	}
}

// change_status shows a change only to the technician who submitted it, and
// for a client-bound session only inside its own client.
func TestGateChangeStatusShowsOnlyTheOwnersChanges(t *testing.T) {
	f := newGateFixture(t)
	alice := f.connect(t, gateBearerAlice)
	bob := f.connect(t, gateBearerBob)
	legacy := f.connect(t, gateBearerLegacy)
	globex := f.connect(t, gateBearerGlobex)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, alice, a, "a")
	sub := f.apply(t, alice, a, planID, digest)
	la := f.grant(t, "alice@msp", "ses_gate", time.Hour, gateChangeOps...)
	planID, digest = f.prepare(t, legacy, la, "b")
	lsub := f.apply(t, legacy, la, planID, digest)

	if st := gateStatus(t, alice, sub.ApprovalID); st.State != model.ChangeAwaiting || st.Link != gateCompanion+"/c/"+sub.ApprovalID ||
		!strings.Contains(st.Message, "Waiting for the technician's approval") {
		t.Errorf("the owner's change_status %+v", st)
	}
	if st := gateStatus(t, legacy, lsub.ApprovalID); st.State != model.ChangeAwaiting {
		t.Errorf("the client-bound owner's change_status %+v", st)
	}
	for name, c := range map[string]struct {
		cs *mcp.ClientSession
		id string
	}{
		"another technician":                      {bob, sub.ApprovalID},
		"a client-bound session":                  {legacy, sub.ApprovalID},
		"a technician, for a client-bound change": {alice, lsub.ApprovalID},
		"the same name bound to another client":   {globex, lsub.ApprovalID},
		"an approval that does not exist":         {alice, "chg_nothing"},
	} {
		if text, isErr := call(t, c.cs, ToolChangeStatus, map[string]any{"approval_id": c.id}); !isErr || !strings.HasPrefix(text, proto.ErrNotFound+":") {
			t.Errorf("%s: %q, error %v", name, text, isErr)
		}
	}
	// The other client's session is refused in its own client's chain.
	es := f.entries(t, "globex")
	if len(es) == 0 || es[len(es)-1].Tool != ToolChangeStatus || es[len(es)-1].Result != audit.ResultDenied {
		t.Errorf("globex chain %+v", es)
	}
}

// A change submitted by a client-bound session is released as that session,
// and not at all once the session has been revoked.
func TestGateReleasesAsTheClientBoundSessionThatSubmitted(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerLegacy)
	a := f.grant(t, "alice@msp", "ses_gate", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	if got := f.approve(t, f.apply(t, cs, a, planID, digest).ApprovalID, "cred-legacy"); got.State != model.ChangeApplied {
		t.Fatalf("a client-bound session's change: %+v", got)
	}
	if req := f.ep.requests(proto.OpApplyFileChange)[0]; req.Caller.Session != "ses_gate" || req.Caller.Tech != "alice@msp" {
		t.Errorf("released as %+v", req.Caller)
	}

	planID, digest = f.prepare(t, cs, a, "b")
	sub := f.apply(t, cs, a, planID, digest)
	revoked := f.clock.now()
	f.dir.update(func(d *fakeDir) {
		s := d.sessions[gateBearerLegacy]
		s.RevokedAt = &revoked
		d.sessions[gateBearerLegacy] = s
	})
	got := f.approve(t, sub.ApprovalID, "cred-legacy")
	if got.State != model.ChangeRefused || got.ErrorCode != proto.ErrUnauthorized {
		t.Fatalf("a revoked session's change: %+v", got)
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 1 {
		t.Errorf("a revoked session's change reached the machine (%d applies)", n)
	}
	if rel := f.releases(t, got.RequestID); len(rel) != 1 || rel[0].Result != audit.ResultDenied || rel[0].ErrorCode != proto.ErrUnauthorized {
		t.Errorf("the refused release was audited as %+v", rel)
	}
}

// The reconcile loop leaves a change alone while it is being released: two
// releases of one approval at once could record a refusal over a change the
// other applied.
func TestGateNeverReleasesTheSameChangeTwiceAtOnce(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	sub := f.apply(t, cs, a, planID, digest)
	var once sync.Once
	f.ep.set(func(ep *gateEndpoint) {
		ep.during = func(req proto.Request) {
			if req.Op == proto.OpApplyFileChange {
				once.Do(func() { f.g.reconcileChanges(ctx) }) // the loop ticks mid-release
			}
		}
	})
	if got := f.approve(t, sub.ApprovalID, "cred-alice"); got.State != model.ChangeApplied {
		t.Fatalf("after approval: %+v", got)
	}
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 1 {
		t.Fatalf("one approval was released %d times", n)
	}
}

func TestGatePurgesPlansNobodyNeeds(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, _ := f.prepare(t, cs, a, "a")
	f.advance(model.ApprovalRetention + time.Minute)
	f.g.reconcileChanges(context.Background())
	if _, err := f.st.ChangePlan(context.Background(), planID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("a plan prepared a day ago survived the reconcile loop: %v", err)
	}
}

// No tool the model can call approves a change; the change tools send it to
// the technician's companion and to change_status.
func TestGateToolsNeverOfferTheModelAnApproval(t *testing.T) {
	f := newGateFixture(t)
	for _, bearer := range []string{gateBearerAlice, gateBearerLegacy} {
		res, err := f.connect(t, bearer).ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		desc := map[string]string{}
		for _, tool := range res.Tools {
			desc[tool.Name] = tool.Description
			if strings.Contains(tool.Name, "approve") {
				t.Errorf("%s offers the model a tool named %s", bearer, tool.Name)
			}
		}
		if _, ok := desc[ToolChangeStatus]; !ok {
			t.Errorf("%s has no %s", bearer, ToolChangeStatus)
		}
		for _, name := range []string{proto.OpApplyFileChange, proto.OpRollbackFileChange} {
			if !strings.Contains(desc[name], "companion") || !strings.Contains(desc[name], ToolChangeStatus) {
				t.Errorf("%s description: %s", name, desc[name])
			}
		}
		if !strings.Contains(desc[proto.OpPrepareFileChange], "dry run") {
			t.Errorf("prepare description: %s", desc[proto.OpPrepareFileChange])
		}
	}
}

// gateFailingAudit is an audit store that refuses the entries fail picks.
type gateFailingAudit struct {
	audit.Store
	fail func(*audit.Entry) bool
}

func (s gateFailingAudit) Append(ctx context.Context, e *audit.Entry) error {
	if s.fail(e) {
		return errors.New("audit store unavailable")
	}
	return s.Store.Append(ctx, e)
}

// A release never writes what the audit log cannot show was approved: an
// approval whose record fails is not released, then or later.
func TestGateDoesNotReleaseAnApprovalItCannotAudit(t *testing.T) {
	f := newGateFixture(t, func(cfg *Config) {
		cfg.Audit = gateFailingAudit{Store: cfg.Audit, fail: func(e *audit.Entry) bool { return e.Tool == "change."+model.ChangeApproved }}
	})
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	got := f.approve(t, f.apply(t, cs, a, planID, digest).ApprovalID, "cred-alice")
	if got.State != model.ChangeFailed || got.ErrorCode != proto.ErrAuditFailed {
		t.Fatalf("an approval that could not be audited: %+v", got)
	}
	f.g.reconcileChanges(context.Background())
	if n := len(f.ep.requests(proto.OpApplyFileChange)); n != 0 || f.ep.file() != gateOriginal {
		t.Fatalf("an unaudited approval was released (%d applies, file %q)", n, f.ep.file())
	}
}

// A refusal on a retry does not show that nothing was written: an earlier
// release may have been applied with its answer lost. It is recorded as
// failed, with the refusal, never as refused.
func TestGateRecordsARefusedRetryAsFailed(t *testing.T) {
	f := newGateFixture(t)
	cs := f.connect(t, gateBearerAlice)
	a := f.grant(t, "tech_alice", "idp_gate_alice", time.Hour, gateChangeOps...)
	planID, digest := f.prepare(t, cs, a, "a")
	sub := f.apply(t, cs, a, planID, digest)
	f.ep.offline(t)
	if got := f.approve(t, sub.ApprovalID, "cred-alice"); got.State != model.ChangeApproved {
		t.Fatalf("approved while offline: %+v", got)
	}
	f.ep.set(func(ep *gateEndpoint) { ep.refuse = proto.ErrStalePlan })
	f.ep.online(t)
	f.g.reconcileChanges(context.Background())
	row := f.row(t, sub.ApprovalID)
	if row.State != model.ChangeFailed || row.ErrorCode != proto.ErrStalePlan || !strings.Contains(row.Reason, "unknown") {
		t.Fatalf("a refused retry: %+v", row)
	}
	if e, ok := f.consent(t, row.ID, model.ChangeFailed); !ok || e.Result != audit.ResultError {
		t.Errorf("change.failed entry %+v", e)
	}
	if _, ok := f.consent(t, row.ID, model.ChangeRefused); ok {
		t.Error("a refused retry was recorded as refused")
	}
}

// Without technician approval the gate is off: the companion never runs
// there, and nothing in the gate touches a store that does not exist.
func TestGateIsOffWithoutApprovals(t *testing.T) {
	g := &Gateway{}
	if _, err := g.ApproveChange(context.Background(), "chg_x", proto.TechnicianApproval{}); !errors.Is(err, model.ErrInvalid) {
		t.Errorf("ApproveChange = %v", err)
	}
	if _, err := g.DenyChange(context.Background(), "chg_x", "tech", "cred"); !errors.Is(err, model.ErrInvalid) {
		t.Errorf("DenyChange = %v", err)
	}
	g.reconcileChanges(context.Background())
}
