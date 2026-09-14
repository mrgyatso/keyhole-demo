package fstools

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// prepareFileChange reads the target, records what it is, validates the
// proposed content, computes a bounded diff, and stages the content in the
// agent's own directory. It does not touch the target.
func (c *call) prepareFileChange(a proto.PrepareFileChangeArgs) (proto.PrepareFileChangeResult, error) {
	var zero proto.PrepareFileChangeResult
	cc, err := c.change()
	if err != nil {
		return zero, err
	}
	content, binaryContent, err := decodeProposed(a)
	if err != nil {
		return zero, err
	}
	if err := cc.store.charge(cc.key, 1, 0); err != nil {
		return zero, err
	}
	t, err := cc.openForChange(a.Path)
	if err != nil {
		return zero, err
	}
	defer t.close()
	size := t.info.Size()
	if size > proto.MaxChangeBytes {
		return zero, failf(proto.ErrTooLarge, "%s is %d bytes; a change is limited to %d", a.Path, size, proto.MaxChangeBytes)
	}
	before, err := readAt(t.file, 0, size)
	if err != nil {
		return zero, failf(proto.ErrIO, "reading %s: %v", a.Path, err)
	}
	identity, err := fileIdentity(t.file, t.info)
	if err != nil {
		return zero, failf(proto.ErrIO, "cannot identify %s: %v", a.Path, err)
	}
	beforeSHA, afterSHA := hashBytes(before), hashBytes(content)
	if a.ExpectSHA256 != "" && !strings.EqualFold(a.ExpectSHA256, beforeSHA) {
		return zero, failf(proto.ErrStalePlan, "%s is sha256 %s, not the %s this change expected", a.Path, beforeSHA, strings.ToLower(a.ExpectSHA256))
	}
	if beforeSHA == afterSHA {
		return zero, failf(proto.ErrBadRequest, "the proposed content is identical to %s; there is nothing to change", a.Path)
	}

	planID := changeID("plan")
	expires := cc.now.Add(proto.ChangePlanTTL)
	if !cc.cap.ExpiresAt.IsZero() && cc.cap.ExpiresAt.Before(expires) {
		expires = cc.cap.ExpiresAt // a plan never outlives the grant that prepared it
	}
	plan := proto.ChangePlan{
		PlanID:      planID,
		PlanDigest:  planDigest(t.path, beforeSHA, afterSHA, planID),
		Op:          proto.OpPrepareFileChange,
		Mode:        mode(a),
		Reason:      a.Reason,
		Before:      proto.FileSnapshot{Path: t.path, Size: size, SHA256: beforeSHA, ModTime: t.info.ModTime().UTC(), Mode: t.info.Mode().String(), Identity: identity},
		AfterSHA256: afterSHA,
		AfterSize:   int64(len(content)),
		Binary:      binaryContent || !utf8.Valid(before),
		PreparedAt:  cc.now,
		ExpiresAt:   expires,
	}
	if !plan.Binary {
		// The diff carries file content, so it is redacted like any other
		// text this agent returns.
		diff, lines, truncated := unifiedDiff(string(before), string(content), t.path)
		redacted, n, rules := cc.redact(diff)
		cc.noteRedactions(n, rules)
		plan.Diff, plan.DiffLines, plan.DiffTruncated = redacted, lines, truncated
	}

	if err := cc.store.reserve(cc.now, int64(len(content))); err != nil {
		return zero, err
	}
	rec := &planRecord{Version: storeVersion, Plan: plan, AccessID: cc.cap.AccessID, GrantID: cc.cap.GrantID,
		Technician: cc.cap.Technician, State: planStaged}
	if cc.reviewedAtMachine() {
		rec.Review = reviewAwaiting
	}
	if err := writeFileSync(cc.store.contentPath(planID), content); err != nil {
		return zero, failf(proto.ErrIO, "could not stage the proposed content: %v", err)
	}
	if err := cc.store.savePlan(rec); err != nil {
		cc.store.remove(cc.store.contentPath(planID))
		return zero, failf(proto.ErrIO, "could not stage the change plan: %v", err)
	}
	// The plan is on disk before anyone is shown it, so the answer always has a
	// record to land on; a review that cannot be shown takes the plan back out.
	if err := cc.review(rec); err != nil {
		cc.store.remove(cc.store.planPath(planID), cc.store.contentPath(planID))
		return zero, err
	}
	cc.noteChange(proto.ChangeMeta{PlanID: planID, PlanDigest: plan.PlanDigest, BeforeSHA256: beforeSHA,
		AfterSHA256: afterSHA, BytesChanged: int64(len(content))})
	return proto.PrepareFileChangeResult{ChangePlan: plan, Approved: rec.Approved, Approver: rec.Approver, Review: rec.Review}, nil
}

// review shows the staged plan to the person at the machine and returns
// without waiting for them, the way an access request does: a person reading
// a diff and answering Windows' elevation prompt takes longer than any request
// should be held open. Their answer is recorded on the plan whenever it comes,
// and apply refuses the plan until it says approved. With no approver
// configured the plan is staged unsigned: the gates are then the capability
// and the digest the relay recorded on the grant. Under a technician grant
// the machine is asked only when the client's policy says so; the gate is
// otherwise the technician's approval of the apply (checkChangeApproval).
func (cc *changeCall) review(rec *planRecord) error {
	if !cc.reviewedAtMachine() {
		return nil
	}
	raw, err := json.Marshal(rec.Plan)
	if err != nil {
		return failf(proto.ErrInternal, "the plan could not be encoded for review")
	}
	cr := proto.ConsentRequest{PlanDigest: rec.Plan.PlanDigest, Plan: raw, AccessID: cc.cap.AccessID,
		Client: cc.cap.Client, Device: cc.cap.Device, Technician: cc.cap.Technician, Purpose: rec.Plan.Reason,
		Operations: []string{proto.OpApplyFileChange}, Paths: []string{rec.Plan.Before.Path},
		ExpiresAt: rec.Plan.ExpiresAt, PolicyVersion: cc.cap.PolicyVersion}
	// The review must not end with this request; it ends with the plan. The
	// approver also ends it early when the grant ends.
	ctx, cancel := context.WithDeadline(context.WithoutCancel(cc.ctx), rec.Plan.ExpiresAt)
	answers, err := cc.store.approver.ReviewChange(ctx, cr)
	if err != nil {
		cancel()
		return failf(proto.ErrConsentRequired, "the change could not be shown to the person at the machine: %v", err)
	}
	go cc.store.recordReview(ctx, cancel, rec.Plan.PlanID, rec.Plan.PlanDigest, answers)
	return nil
}

// recordReview waits for the one answer to a plan's review and records it on
// the staged plan.
func (s *changeStore) recordReview(ctx context.Context, done context.CancelFunc, planID, digest string, answers <-chan proto.ConsentDecision) {
	var (
		d        proto.ConsentDecision
		answered bool
	)
	select {
	case d, answered = <-answers:
	case <-ctx.Done():
	}
	done()
	s.settleReview(planID, digest, d, answered)
	if s.reviewed != nil {
		s.reviewed(planID)
	}
}

// settleReview records a review's outcome under the store's lock, so an apply
// sees the plan either before the answer or after it. Only an approval that
// signs this exact plan and names who gave it approves anything; every other
// outcome leaves the plan unapproved for good.
func (s *changeStore) settleReview(planID, digest string, d proto.ConsentDecision, answered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.loadPlan(planID)
	if err != nil {
		s.log.Info("fstools: a reviewed plan is no longer staged", "plan_id", planID, "err", err)
		return
	}
	if rec.State != planStaged || rec.Review != reviewAwaiting {
		return
	}
	switch {
	case !answered:
		rec.Review = reviewEnded
	case d.State == proto.ConsentDenied:
		rec.Review = reviewDenied
	case d.State != proto.ConsentApproved:
		rec.Review = reviewEnded
	case digest != rec.Plan.PlanDigest || subtle.ConstantTimeCompare([]byte(d.PlanDigest), []byte(digest)) != 1:
		s.log.Warn("fstools: a change review signed another plan; this plan stays unapproved", "plan_id", planID)
		rec.Review = reviewEnded
	case d.Approver == "":
		s.log.Warn("fstools: a change review named no approver; this plan stays unapproved", "plan_id", planID)
		rec.Review = reviewEnded
	default:
		rec.Review, rec.Approved, rec.Approver = reviewApproved, true, d.Approver
	}
	if err := s.savePlan(rec); err != nil {
		s.log.Error("fstools: could not record a change review; the plan stays unapproved", "plan_id", planID, "err", err)
		return
	}
	s.log.Info("fstools: change review answered", "plan_id", planID, "review", rec.Review, "approver", rec.Approver)
}

// unreviewed says why a plan that needs the local review's approval cannot be
// applied: not yet, or not at all. Under a technician grant the caller does
// not deal with the person at the machine, so it is not told to ask them.
func unreviewed(rec *planRecord, technician bool) error {
	id := rec.Plan.PlanID
	switch rec.Review {
	case reviewAwaiting:
		if technician {
			return failf(proto.ErrConsentRequired, "this client's policy also needs the person at the machine to approve plan %s, and they have not answered yet; nothing was written", id)
		}
		return failf(proto.ErrConsentRequired, "plan %s is waiting for the person at the machine to review it; ask them to approve it in the Keyhole window, then call apply_file_change again", id)
	case reviewDenied:
		return failf(proto.ErrConsentRequired, "the person at the machine refused plan %s; nothing was written", id)
	case reviewEnded:
		return failf(proto.ErrConsentRequired, "the review of plan %s ended without an approval (it expired, the access grant ended, or a newer change replaced it); prepare the change again", id)
	}
	return failf(proto.ErrConsentRequired, "plan %s was never approved at the machine", id)
}

// checkChangeApproval is the gate every write under a technician grant passes
// before anything is written. The request must carry the technician's signed
// approval of exactly this write: this op, on this plan (and for a rollback
// this rollback copy), under this grant, for this client and device, and still
// valid by the endpoint's clock, allowing proto.ApprovalClockSkew. Anything
// else is refused with proto.ErrApprovalRequired.
//
// In Slice 6 the endpoint trusts the relay's verification of the passkey
// assertion behind the approval. Slice 7 verifies a.Assertion against
// a.Challenge() here, with the technician's key from the MSP-signed key list
// the endpoint pinned at enrollment.
//
// resuming relaxes the expiry alone, as apply relaxes the plan's own: an
// attempt by this request ID has already passed this gate and may already
// have replaced the target, so finishing it must not depend on how long the
// retry took.
func (cc *changeCall) checkChangeApproval(a *proto.TechnicianApproval, planID, planDigest, rollbackID string, resuming bool) error {
	if a == nil {
		return failf(proto.ErrApprovalRequired, "this access grant came from a technician unlock, so %s needs the technician's approval of exactly this change, and the request carries none; nothing was written", cc.op)
	}
	var why string
	switch {
	case a.Kind != proto.ApprovalChange || a.ID == "" || !a.Signed():
		why = "it is not a signed change approval"
	case a.Op != cc.op:
		why = "it approves another operation"
	case a.Technician != cc.cap.Technician || a.Client != cc.cap.Client || a.Device != cc.cap.Device ||
		a.AccessID != cc.cap.AccessID || a.GrantID != cc.cap.GrantID:
		why = "it was given for another technician, client, device or access grant"
	case !constantTimeEqual(a.PlanID, planID) || !constantTimeEqual(a.PlanDigest, planDigest):
		why = "it approves another plan"
	case !constantTimeEqual(a.RollbackID, rollbackID):
		why = "it approves another rollback copy"
	case !resuming && !cc.now.Before(a.ExpiresAt.Add(proto.ApprovalClockSkew)):
		why = "it expired at " + a.ExpiresAt.UTC().Format(time.RFC3339)
	default:
		return nil
	}
	return failf(proto.ErrApprovalRequired, "the technician approval on this request does not release this %s: %s; nothing was written", cc.op, why)
}

// recordApproval names who approved a change applied under a technician
// grant: the technician, and the person at the machine as well when the
// client's policy asked them. A plan is applied once, so the first approval
// recorded is the one that released the write, and finishing an interrupted
// apply keeps it rather than naming the machine's approver twice.
func recordApproval(rec *planRecord, a *proto.TechnicianApproval) {
	if rec.ApprovalID != "" {
		return
	}
	label := a.ApproverLabel()
	if rec.Approved && rec.Approver != "" {
		label += "; at the machine: " + rec.Approver
	}
	rec.Approver, rec.ApprovalID = label, a.ID
}

// constantTimeEqual compares two strings without letting the time it takes
// say how much of one a caller got right.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// applyFileChange applies a staged plan: it verifies the target is still the
// file the plan reviewed, saves a rollback copy, writes through a
// same-directory temporary file, and replaces the target atomically.
func (c *call) applyFileChange(a proto.ApplyFileChangeArgs) (proto.ApplyFileChangeResult, error) {
	var zero, out proto.ApplyFileChangeResult
	cc, err := c.change()
	if err != nil {
		return zero, err
	}
	replayed, err := cc.replay(&out)
	if err != nil {
		return zero, err
	}
	if replayed {
		out.Replayed = true
		return out, nil
	}
	if !cc.store.mu.TryLock() {
		return zero, failf(proto.ErrConflict, "another change is in progress on this machine; retry when it finishes")
	}
	defer cc.store.mu.Unlock()

	rec, err := cc.plan(a.PlanID)
	if err != nil {
		return zero, err
	}
	if subtle.ConstantTimeCompare([]byte(a.PlanDigest), []byte(rec.Plan.PlanDigest)) != 1 {
		return zero, failf(proto.ErrStalePlan, "plan %s has digest %s, not the one this request quotes", a.PlanID, rec.Plan.PlanDigest)
	}
	if rec.AccessID != cc.cap.AccessID || rec.GrantID != cc.cap.GrantID {
		return zero, failf(proto.ErrGrantInvalid, "plan %s was prepared under another access grant", a.PlanID)
	}
	resume, resuming := cc.resume(rec)
	if cc.technician() {
		if err := cc.checkChangeApproval(a.Approval, a.PlanID, a.PlanDigest, "", resuming); err != nil {
			return zero, err
		}
	}
	if cc.reviewedAtMachine() && !rec.Approved {
		return zero, unreviewed(rec, cc.technician())
	}
	if rec.State != planStaged && !resuming {
		return zero, failf(proto.ErrStalePlan, "plan %s is %s; prepare a new change", a.PlanID, rec.State)
	}
	if !cc.now.Before(rec.Plan.ExpiresAt) && !resuming {
		return zero, failf(proto.ErrStalePlan, "plan %s expired at %s; prepare a new change", a.PlanID, rec.Plan.ExpiresAt.Format(time.RFC3339))
	}
	staged, err := os.ReadFile(cc.store.contentPath(a.PlanID))
	if err != nil {
		return zero, failf(proto.ErrStalePlan, "the content staged for plan %s is gone; prepare a new change", a.PlanID)
	}
	if hashBytes(staged) != rec.Plan.AfterSHA256 {
		return zero, failf(proto.ErrInternal, "the content staged for plan %s does not match its digest; nothing was written", a.PlanID)
	}

	t, current, identity, err := cc.reopen(rec)
	if err != nil {
		return zero, err
	}
	defer t.close()
	// An interrupted attempt that already replaced the target: finish its
	// bookkeeping instead of writing again.
	if resuming && current == rec.Plan.AfterSHA256 {
		rec.AppliedIdentity = identity
		return cc.finishApply(rec, resume.RollbackID, int64(len(staged)), true, a.Approval)
	}
	if !sameFile(rec.Plan.Before.Identity, identity) {
		return zero, failf(proto.ErrStalePlan, "%s is no longer the same file the plan reviewed; it was replaced", t.path)
	}
	if current != rec.Plan.Before.SHA256 {
		return zero, failf(proto.ErrStalePlan, "%s is sha256 %s, not the %s this plan reviewed; it changed after review",
			rec.Plan.Before.Path, current, rec.Plan.Before.SHA256)
	}
	if err := cc.store.charge(cc.key, 1, int64(len(staged))); err != nil {
		return zero, err
	}
	before, err := readAt(t.file, 0, t.info.Size())
	if err != nil {
		return zero, failf(proto.ErrIO, "reading %s: %v", rec.Plan.Before.Path, err)
	}
	if err := cc.store.reserve(cc.now, int64(len(before))); err != nil {
		return zero, err
	}
	rollbackID := changeID("rb")
	if err := writeFileSync(cc.store.rollbackPath(rollbackID), before); err != nil {
		return zero, failf(proto.ErrIO, "could not save the rollback copy: %v", err)
	}
	if err := cc.replaceContent(t, rec.Plan.PlanID, rollbackID, staged); err != nil {
		cc.store.remove(cc.store.rollbackPath(rollbackID))
		return zero, err
	}
	written, err := cc.verify(rec.Plan.Before.Path, rec.Plan.AfterSHA256)
	if err != nil {
		return zero, err
	}
	rec.AppliedIdentity = written
	return cc.finishApply(rec, rollbackID, int64(len(staged)), false, a.Approval)
}

// finishApply records the applied plan and journals the result. Both the plan
// record and the journal entry are written after the target is already the new
// content, so a crash here is reconciled on the next attempt. approval is the
// technician approval checkChangeApproval accepted, under a technician grant.
func (cc *changeCall) finishApply(rec *planRecord, rollbackID string, written int64, resumed bool, approval *proto.TechnicianApproval) (proto.ApplyFileChangeResult, error) {
	rec.State, rec.AppliedAt = planApplied, cc.now
	rec.RollbackID, rec.RollbackSHA = rollbackID, rec.Plan.Before.SHA256
	if cc.technician() {
		recordApproval(rec, approval)
	}
	// A rollback copy is kept for the retention window or until the grant that
	// made it ends, whichever comes first. The capability's own expiry is the
	// grant's hard end, so a copy never outlives the authority that created it.
	rec.RollbackUntil = cc.now.Add(proto.RollbackRetention)
	if !cc.cap.ExpiresAt.IsZero() && cc.cap.ExpiresAt.Before(rec.RollbackUntil) {
		rec.RollbackUntil = cc.cap.ExpiresAt
	}
	if err := cc.store.savePlan(rec); err != nil {
		return proto.ApplyFileChangeResult{}, failf(proto.ErrIO, "the change was applied but its plan could not be updated: %v", err)
	}
	out := proto.ApplyFileChangeResult{
		PlanID: rec.Plan.PlanID, PlanDigest: rec.Plan.PlanDigest, Path: rec.Plan.Before.Path,
		BeforeSHA256: rec.Plan.Before.SHA256, AfterSHA256: rec.Plan.AfterSHA256, BytesWritten: written,
		RollbackID: rollbackID, RollbackPath: cc.store.rollbackPath(rollbackID),
		RollbackTill: rec.RollbackUntil, AppliedAt: cc.now, Replayed: resumed,
	}
	change := proto.ChangeMeta{PlanID: rec.Plan.PlanID, PlanDigest: rec.Plan.PlanDigest, Approver: rec.Approver,
		ApprovalID: rec.ApprovalID, BeforeSHA256: out.BeforeSHA256, AfterSHA256: out.AfterSHA256, BytesChanged: written,
		RollbackPath: out.RollbackPath, Replayed: resumed}
	if err := cc.commit(rec.Plan.PlanID, out, change); err != nil {
		return proto.ApplyFileChangeResult{}, err
	}
	cc.noteChange(change)
	return out, nil
}

// rollbackFileChange restores the copy an apply saved. It refuses unless the
// target still holds exactly what that apply wrote: anything else would
// silently discard a third party's change.
func (c *call) rollbackFileChange(a proto.RollbackFileChangeArgs) (proto.RollbackFileChangeResult, error) {
	var zero, out proto.RollbackFileChangeResult
	cc, err := c.change()
	if err != nil {
		return zero, err
	}
	replayed, err := cc.replay(&out)
	if err != nil {
		return zero, err
	}
	if replayed {
		out.Replayed = true
		return out, nil
	}
	if !cc.store.mu.TryLock() {
		return zero, failf(proto.ErrConflict, "another change is in progress on this machine; retry when it finishes")
	}
	defer cc.store.mu.Unlock()

	rec, err := cc.plan(a.PlanID)
	if err != nil {
		return zero, err
	}
	switch {
	case rec.State != planApplied:
		return zero, failf(proto.ErrStalePlan, "plan %s is %s; there is nothing to roll back", a.PlanID, rec.State)
	case rec.Technician != cc.cap.Technician:
		return zero, failf(proto.ErrGrantInvalid, "plan %s was applied by another technician", a.PlanID)
	case a.RollbackID != "" && a.RollbackID != rec.RollbackID:
		return zero, failf(proto.ErrStalePlan, "plan %s has no rollback copy %s", a.PlanID, a.RollbackID)
	case !cc.now.Before(rec.RollbackUntil):
		return zero, failf(proto.ErrStalePlan, "the rollback copy for plan %s expired at %s", a.PlanID, rec.RollbackUntil.Format(time.RFC3339))
	}
	// A rollback writes, so under a technician grant it needs an approval of
	// its own: the apply's names another operation, and binds no rollback.
	if cc.technician() {
		if err := cc.checkChangeApproval(a.Approval, a.PlanID, rec.Plan.PlanDigest, a.RollbackID, false); err != nil {
			return zero, err
		}
	}
	saved, err := os.ReadFile(cc.store.rollbackPath(rec.RollbackID))
	if err != nil {
		return zero, failf(proto.ErrStalePlan, "the rollback copy for plan %s is gone", a.PlanID)
	}
	if hashBytes(saved) != rec.RollbackSHA {
		return zero, failf(proto.ErrInternal, "the rollback copy for plan %s does not match its recorded hash; nothing was written", a.PlanID)
	}
	t, current, identity, err := cc.reopen(rec)
	if err != nil {
		return zero, err
	}
	defer t.close()
	if !sameFile(rec.AppliedIdentity, identity) {
		return zero, failf(proto.ErrStalePlan, "%s is no longer the file this change wrote; it was replaced", t.path)
	}
	if current != rec.Plan.AfterSHA256 {
		return zero, failf(proto.ErrStalePlan, "%s is sha256 %s, not the %s this change wrote; it was changed again, so rolling back would discard that change",
			rec.Plan.Before.Path, current, rec.Plan.AfterSHA256)
	}
	if err := cc.store.charge(cc.key, 1, int64(len(saved))); err != nil {
		return zero, err
	}
	if err := cc.replaceContent(t, rec.Plan.PlanID, rec.RollbackID, saved); err != nil {
		return zero, err
	}
	if _, err := cc.verify(rec.Plan.Before.Path, rec.RollbackSHA); err != nil {
		return zero, err
	}
	rec.State = planRolledBack
	if err := cc.store.savePlan(rec); err != nil {
		return zero, failf(proto.ErrIO, "the file was restored but its plan could not be updated: %v", err)
	}
	out = proto.RollbackFileChangeResult{PlanID: rec.Plan.PlanID, Path: rec.Plan.Before.Path,
		BeforeSHA256: current, AfterSHA256: rec.RollbackSHA, BytesWritten: int64(len(saved)), RestoredAt: cc.now}
	change := proto.ChangeMeta{PlanID: rec.Plan.PlanID, PlanDigest: rec.Plan.PlanDigest, Approver: rec.Approver, BeforeSHA256: current,
		AfterSHA256: rec.RollbackSHA, BytesChanged: int64(len(saved)), RollbackPath: cc.store.rollbackPath(rec.RollbackID)}
	if cc.technician() {
		// The rollback names its own approver; the apply's stays on the plan.
		change.Approver, change.ApprovalID = a.Approval.ApproverLabel(), a.Approval.ID
	}
	if err := cc.commit(rec.Plan.PlanID, out, change); err != nil {
		return zero, err
	}
	cc.noteChange(change)
	return out, nil
}

// plan loads a staged plan by ID after checking the ID's shape, so an
// argument can never name a file outside the plan directory.
func (cc *changeCall) plan(id string) (*planRecord, error) {
	if !validChangeID("plan", id) {
		return nil, failf(proto.ErrBadRequest, "plan_id is not a plan identifier this agent issued")
	}
	rec, err := cc.store.loadPlan(id)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, failf(proto.ErrStalePlan, "plan %s is unknown or has expired; prepare the change again", id)
	}
	if err != nil {
		return nil, failf(proto.ErrInternal, "plan %s could not be read", id)
	}
	// The plan file lives in the agent's own directory, but recomputing the
	// digest costs nothing and makes a tampered plan unusable.
	if planDigest(rec.Plan.Before.Path, rec.Plan.Before.SHA256, rec.Plan.AfterSHA256, id) != rec.Plan.PlanDigest {
		return nil, failf(proto.ErrInternal, "plan %s does not match its own digest; it will not be applied", id)
	}
	return rec, nil
}

// resume reports an interrupted attempt by this same request ID.
func (cc *changeCall) resume(rec *planRecord) (*journalRecord, bool) {
	j, err := cc.store.loadJournal(cc.id)
	if err != nil || j.State != journalIntent || j.PlanID != rec.Plan.PlanID {
		return nil, false
	}
	return j, true
}

// reopen resolves the plan's target again, with every check a first open
// makes, and returns it with the hash of its current content. A path that now
// leads somewhere else, or to something that is no longer an ordinary file,
// fails here.
func (cc *changeCall) reopen(rec *planRecord) (*target, string, proto.FileIdentity, error) {
	var none proto.FileIdentity
	t, err := cc.openForChange(rec.Plan.Before.Path)
	if err != nil {
		return nil, "", none, err
	}
	fail := func(err error) (*target, string, proto.FileIdentity, error) {
		t.close()
		return nil, "", none, err
	}
	if !samePath(cc.goos, t.path, rec.Plan.Before.Path) {
		return fail(failf(proto.ErrStalePlan, "%s now resolves to %s; the plan reviewed a different file", rec.Plan.Before.Path, t.path))
	}
	if size := t.info.Size(); size > proto.MaxChangeBytes {
		return fail(failf(proto.ErrTooLarge, "%s is now %d bytes, over the %d-byte change limit", t.path, size, proto.MaxChangeBytes))
	}
	id, err := fileIdentity(t.file, t.info)
	if err != nil {
		return fail(failf(proto.ErrIO, "cannot identify %s: %v", t.path, err))
	}
	content, err := readAt(t.file, 0, t.info.Size())
	if err != nil {
		return fail(failf(proto.ErrIO, "reading %s: %v", t.path, err))
	}
	return t, hashBytes(content), id, nil
}

// sameFile reports whether the file on disk is the one an earlier step
// recorded. Replacing a file through a rename gives the target a new identity,
// so each step compares against the identity it expects: the one prepare saw
// for a first apply, the one apply wrote for a rollback.
func sameFile(want, got proto.FileIdentity) bool { return want.Zero() || want == got }

// verify reopens the target after a write and confirms it holds exactly what
// was meant to be there. It is what the result and the audit entry promise.
func (cc *changeCall) verify(path, want string) (proto.FileIdentity, error) {
	var none proto.FileIdentity
	t, err := cc.openForChange(path)
	if err != nil {
		return none, failf(proto.ErrIO, "the change was written but %s could not be reopened to verify it: %v", path, err)
	}
	defer t.close()
	content, err := readAt(t.file, 0, t.info.Size())
	if err != nil {
		return none, failf(proto.ErrIO, "the change was written but %s could not be read back: %v", path, err)
	}
	if got := hashBytes(content); got != want {
		return none, failf(proto.ErrInternal, "%s reads back as sha256 %s, not the %s that was written", path, got, want)
	}
	id, err := fileIdentity(t.file, t.info)
	if err != nil {
		return none, failf(proto.ErrIO, "cannot identify %s after writing it: %v", path, err)
	}
	return id, nil
}

// replaceContent writes content through a temporary file in the target's own
// directory and swaps it in atomically, preserving the target's permissions.
// The intent is journalled first, so an interrupted attempt leaves a named
// temporary file that startup cleanup removes and never a partial target.
func (cc *changeCall) replaceContent(t *target, planID, rollbackID string, content []byte) error {
	dir := filepath.Dir(t.rel)
	name := tempPrefix + planID + tempSuffix
	tempRel := name
	if dir != "." {
		tempRel = filepath.Join(dir, name)
	}
	tempPath := filepath.Join(filepath.Dir(t.path), name)
	if err := cc.intent(planID, tempPath, rollbackID); err != nil {
		return err
	}
	// A leftover from an interrupted attempt is garbage by construction.
	if err := t.root.Remove(tempRel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return failf(proto.ErrIO, "could not clear a previous temporary file: %v", err)
	}
	f, err := t.root.OpenFile(tempRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return failf(proto.ErrIO, "could not create a temporary file beside %s: %v", t.path, err)
	}
	written := false
	defer func() {
		if !written {
			_ = t.root.Remove(tempRel)
		}
	}()
	if _, err := f.Write(content); err != nil {
		f.Close()
		return failf(proto.ErrIO, "writing the replacement for %s: %v", t.path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return failf(proto.ErrIO, "flushing the replacement for %s: %v", t.path, err)
	}
	if err := f.Close(); err != nil {
		return failf(proto.ErrIO, "closing the replacement for %s: %v", t.path, err)
	}
	if err := applySecurity(t.root, tempRel, tempPath, t.path, t.info); err != nil {
		return failf(proto.ErrIO, "could not give the replacement %s's permissions: %v", t.path, err)
	}
	// Windows refuses MoveFileEx(REPLACE_EXISTING) while the destination is
	// still open without delete sharing. All policy, identity and hash checks
	// above have consumed this handle; keep the rooted directory open but
	// release the destination immediately before the atomic swap.
	if t.file != nil {
		if err := t.file.Close(); err != nil {
			return failf(proto.ErrIO, "could not release %s before replacing it: %v", t.path, err)
		}
		t.file = nil
	}
	if err := replaceTarget(t.root, tempRel, t.rel, tempPath, t.path); err != nil {
		return failf(proto.ErrIO, "could not replace %s: %v", t.path, err)
	}
	written = true
	if err := syncDir(t.root, dir); err != nil {
		cc.x.log.Warn("fstools: could not flush the directory after a change", "path", t.path, "err", err)
	}
	return nil
}

// decodeProposed validates the proposed content: exactly one representation,
// valid UTF-8 without NUL for text, decodable base64 for binary, and within
// the per-file ceiling.
func decodeProposed(a proto.PrepareFileChangeArgs) ([]byte, bool, error) {
	m := mode(a)
	switch {
	case a.Content != "" && a.ContentBase64 != "":
		return nil, false, failf(proto.ErrBadRequest, "give content or content_base64, not both")
	case a.Content == "" && a.ContentBase64 == "":
		return nil, false, failf(proto.ErrBadRequest, "the proposed content is required")
	case m != proto.ChangeModeText && m != proto.ChangeModeBinary:
		return nil, false, failf(proto.ErrBadRequest, "mode must be %q or %q", proto.ChangeModeText, proto.ChangeModeBinary)
	case m == proto.ChangeModeText && a.ContentBase64 != "":
		return nil, false, failf(proto.ErrBadRequest, "content_base64 needs mode %q", proto.ChangeModeBinary)
	}
	if m == proto.ChangeModeBinary {
		content, err := base64.StdEncoding.DecodeString(a.ContentBase64)
		if err != nil {
			return nil, false, failf(proto.ErrBadRequest, "content_base64 is not valid base64: %v", err)
		}
		if len(content) > proto.MaxChangeBytes {
			return nil, false, failf(proto.ErrTooLarge, "the proposed content is %d bytes; the limit is %d", len(content), proto.MaxChangeBytes)
		}
		return content, true, nil
	}
	switch {
	case len(a.Content) > proto.MaxChangeBytes:
		return nil, false, failf(proto.ErrTooLarge, "the proposed content is %d bytes; the limit is %d", len(a.Content), proto.MaxChangeBytes)
	case !utf8.ValidString(a.Content):
		return nil, false, failf(proto.ErrBadRequest, "text content must be valid UTF-8; use mode %q for anything else", proto.ChangeModeBinary)
	case strings.ContainsRune(a.Content, 0):
		return nil, false, failf(proto.ErrBadRequest, "text content must not contain NUL; use mode %q", proto.ChangeModeBinary)
	}
	return []byte(a.Content), false, nil
}

func mode(a proto.PrepareFileChangeArgs) string {
	if a.Mode == "" {
		return proto.ChangeModeText
	}
	return a.Mode
}

// samePath compares two canonical paths the way the filesystem does.
func samePath(goos, a, b string) bool {
	if _, ok := policy.Rel(goos, a, b); !ok {
		return false
	}
	rel, ok := policy.Rel(goos, b, a)
	return ok && rel == "."
}
