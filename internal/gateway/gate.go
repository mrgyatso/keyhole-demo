package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// The change gate (Slice 6). With technician approval on, apply_file_change
// and rollback_file_change contact no machine: each stores a change approval
// and answers awaiting_approval with a companion link. The technician approves
// it on the plan's exact diff with a passkey, the companion calls
// ApproveChange, and only then is the operation released to the endpoint,
// carrying the signed approval, through the same admission, capability,
// integrity and audit path as any tool call. Built against
// docs/handoffs/2026-09-11-slice-6-contract.md, section B2.

// ToolChangeStatus reports what became of a submitted change.
const ToolChangeStatus = "change_status"

// ChangeStatusInput is the input of change_status.
type ChangeStatusInput struct {
	ApprovalID string `json:"approval_id" jsonschema:"Approval ID returned by apply_file_change or rollback_file_change."`
}

// ChangeSubmission is what apply_file_change and rollback_file_change answer
// under technician approval.
type ChangeSubmission struct {
	ApprovalID string    `json:"approval_id"`
	State      string    `json:"state"`
	Op         string    `json:"op"`
	PlanID     string    `json:"plan_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	Link       string    `json:"link,omitempty"`
	Message    string    `json:"message"`
}

// ChangeStatus is the change_status result.
type ChangeStatus struct {
	ApprovalID  string          `json:"approval_id"`
	State       string          `json:"state"`
	Op          string          `json:"op"`
	Device      string          `json:"device"`
	AccessID    string          `json:"access_id"`
	PlanID      string          `json:"plan_id"`
	RollbackID  string          `json:"rollback_id,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"` // what the machine reported, once applied
	Link        string          `json:"link,omitempty"`
	Message     string          `json:"message"`
}

// changeSubmission is one apply or rollback a tool call submits.
type changeSubmission struct {
	op, device, accessID, planID, planDigest, rollbackID string
}

// errGateOff refuses the gate's methods on a relay without technician
// approval; the companion never runs there.
var errGateOff = fmt.Errorf("gateway: technician approval is off: %w", model.ErrInvalid)

// ----- prepare -----

// recordChangePlan keeps the relay's copy of a prepared plan, diff included,
// so the companion can show the technician exactly what they are approving and
// a submitted apply can be checked against it. A plan ID already recorded for
// the same grant, technician and digest is the same plan again.
func (g *Gateway) recordChangePlan(ctx context.Context, a model.AccessRequest, p proto.ChangePlan) *callError {
	raw, err := json.Marshal(p)
	if err != nil {
		return failed(proto.ErrInternal, "the machine's change plan could not be encoded")
	}
	rec := model.ChangePlanRecord{PlanID: p.PlanID, AccessID: a.ID, Client: a.Client, Device: a.Device,
		Technician: a.Technician, Digest: p.PlanDigest, Plan: raw, PreparedAt: g.now().UTC(), ExpiresAt: p.ExpiresAt.UTC()}
	err = g.approvals.CreateChangePlan(ctx, rec)
	if errors.Is(err, model.ErrConflict) {
		prev, perr := g.approvals.ChangePlan(ctx, p.PlanID)
		if perr == nil && prev.AccessID == rec.AccessID && prev.Technician == rec.Technician && prev.Digest == rec.Digest {
			return nil
		}
	}
	if err != nil {
		g.log.Error("gateway: could not record a prepared plan", "access", a.ID, "plan", p.PlanID, "err", err)
		return failed(proto.ErrInternal, "the change plan could not be recorded for the technician's review, so it cannot be submitted")
	}
	return nil
}

// ----- submit -----

// submitChange is apply_file_change and rollback_file_change under technician
// approval. It checks what the release will need (the caller, the client, the
// grant, and the relay's copy of the plan) but contacts no machine: it stores
// a change approval, or finds the pending one for the same plan, and tells the
// model where the technician approves it. It is audited like any tool call.
func (g *Gateway) submitChange(ctx context.Context, c caller, s changeSubmission, input json.RawMessage) *mcp.CallToolResult {
	unlock := g.budgets.lock(c.session.ID)
	defer unlock()
	began := time.Now()
	e := g.entry(c, s.op, input)
	if c.technician {
		e.Client = g.auditClient(ctx, c)
	}
	out, cerr := g.changeSubmit(ctx, c, s, input, &e)
	e.DurationMS = time.Since(began).Milliseconds()
	return g.finish(ctx, c, &e, out, cerr)
}

func (g *Gateway) changeSubmit(ctx context.Context, c caller, s changeSubmission, input json.RawMessage, e *audit.Entry) (*mcp.CallToolResult, *callError) {
	grant, dev, cerr := g.admitChange(ctx, c, s, input, e)
	if cerr != nil {
		return nil, cerr
	}
	// Submitting a change is using the unlock, though no machine is reached.
	g.touchUnlock(ctx, grant.Unlock)
	switch {
	case strings.TrimSpace(s.planID) == "" && s.op == proto.OpRollbackFileChange:
		return nil, denied(proto.ErrBadRequest, "plan_id is required; it is the plan apply_file_change applied")
	case strings.TrimSpace(s.planID) == "" || (s.op == proto.OpApplyFileChange && strings.TrimSpace(s.planDigest) == ""):
		return nil, denied(proto.ErrBadRequest, "plan_id and plan_digest come from prepare_file_change and are both required")
	}
	now := g.now()
	plan, err := g.approvals.ChangePlan(ctx, s.planID)
	switch {
	// A plan prepared under another grant, or by another technician, is
	// indistinguishable from one that does not exist.
	case errors.Is(err, model.ErrNotFound) || (err == nil && (plan.AccessID != grant.ID || plan.Technician != c.session.Tech)):
		return nil, denied(proto.ErrGrantInvalid, "this access grant has no prepared plan with that ID; call prepare_file_change")
	case err != nil:
		g.log.Error("gateway: plan lookup failed", "plan", s.planID, "err", err)
		return nil, failed(proto.ErrInternal, "the prepared plan could not be read")
	}
	// The approval is the card's deadline and the validity the endpoint
	// enforces, so it never outlives what it approves: an apply ends with its
	// plan, and either op with its grant. A rollback's plan has usually expired
	// by design; its rollback copy is the endpoint's to check.
	expires := now.Add(model.ChangeApprovalWindow)
	if s.op == proto.OpApplyFileChange {
		switch {
		case subtle.ConstantTimeCompare([]byte(s.planDigest), []byte(plan.Digest)) != 1:
			return nil, denied(proto.ErrStalePlan, "plan_digest is not this plan's digest; prepare the change again and submit the plan it returns")
		case !now.Before(plan.ExpiresAt):
			return nil, denied(proto.ErrStalePlan, fmt.Sprintf("plan %s expired at %s; prepare the change again", plan.PlanID, plan.ExpiresAt.UTC().Format(time.RFC3339)))
		}
		if plan.ExpiresAt.Before(expires) {
			expires = plan.ExpiresAt
		}
	}
	if grant.ExpiresAt.Before(expires) {
		expires = grant.ExpiresAt
	}

	// One plan gets one card: a second submit while the first is waiting for
	// the technician, or being released, answers with that one.
	pending, err := g.approvals.ChangeApprovalFor(ctx, grant.ID, plan.PlanID, s.op, model.ChangeAwaiting, model.ChangeApproved)
	switch {
	case err == nil && pending.RollbackID == s.rollbackID:
		if state, _ := pending.Due(now); state != model.ChangeExpired {
			e.RequestID = pending.ID
			return g.submitted(pending, e)
		}
		// It lapsed unanswered and the reconcile loop has not caught up yet.
		g.expireChange(ctx, pending)
	case err != nil && !errors.Is(err, model.ErrNotFound):
		g.log.Error("gateway: pending change approval lookup failed", "access", grant.ID, "plan", plan.PlanID, "err", err)
		return nil, failed(proto.ErrInternal, "pending change approvals could not be read")
	}

	nonce, err := newChangeNonce()
	if err != nil {
		return nil, failed(proto.ErrInternal, "could not draw a nonce for the approval")
	}
	row := model.ChangeApproval{ID: model.NewID(model.PrefixChange), Op: s.op, Technician: c.session.Tech,
		Client: grant.Client, Device: dev.ID, AccessID: grant.ID, GrantID: grant.GrantID, Session: c.session.ID,
		PlanID: plan.PlanID, PlanDigest: plan.Digest, RollbackID: s.rollbackID, State: model.ChangeAwaiting,
		RequestedAt: now.UTC(), ExpiresAt: expires.UTC(), Nonce: nonce, RequestID: model.NewID(model.PrefixRequest)}
	if err := g.approvals.CreateChangeApproval(ctx, row); err != nil {
		g.log.Error("gateway: could not store a change approval", "access", grant.ID, "plan", plan.PlanID, "err", err)
		return nil, failed(proto.ErrInternal, "the change could not be submitted for approval")
	}
	e.RequestID = row.ID
	if err := g.auditChange(ctx, row); err != nil {
		return nil, failed(proto.ErrAuditFailed, "the change was submitted for approval but could not be audited")
	}
	return g.submitted(row, e)
}

// admitChange is the admission a submitted change shares with every device
// call (see doOp): the caller's session, the technician's client ACL or the
// legacy client binding, the client kill switch, the device, and a usable
// grant of the caller's that includes the op. Nothing reaches the machine.
func (g *Gateway) admitChange(ctx context.Context, c caller, s changeSubmission, input json.RawMessage, e *audit.Entry) (model.AccessRequest, model.Device, *callError) {
	var (
		grant     model.AccessRequest
		haveGrant bool
		slug      string
	)
	if strings.TrimSpace(s.accessID) == "" {
		return grant, model.Device{}, denied(proto.ErrGrantInvalid, s.op+" needs the access grant the plan was prepared under; pass its access_id")
	}
	if c.technician {
		a, err := g.access.Access(ctx, s.accessID)
		if err != nil || a.Technician != c.session.Tech {
			return grant, model.Device{}, denied(proto.ErrGrantInvalid, "access grant not found")
		}
		grant, haveGrant, slug = a, true, a.Client
	}
	client, cerr := g.admitClient(ctx, c, slug)
	if cerr != nil {
		return grant, model.Device{}, cerr
	}
	e.Client = client.Slug
	dev, cerr := g.resolveDevice(ctx, client.Slug, s.device)
	if cerr != nil {
		return grant, dev, cerr
	}
	e.DeviceID, e.DeviceKey, e.Hostname, e.AgentVersion = dev.ID, dev.PublicKey, dev.Hostname, dev.AgentVersion
	now := g.now()
	// An offline machine can still be submitted to: the release waits for it.
	// A revoked or expired one never comes back.
	if dev.RevokedAt != nil || dev.Expired(now) {
		return grant, dev, denied(proto.ErrDeviceRevoked, deviceLabel(dev)+" is revoked or its temporary session has ended")
	}
	if !haveGrant {
		a, err := g.access.Access(ctx, s.accessID)
		if err != nil {
			return grant, dev, denied(proto.ErrGrantInvalid, "access grant does not belong to this client and device")
		}
		grant = a
	}
	switch {
	case grant.Client != client.Slug || grant.Device != dev.ID:
		return grant, dev, denied(proto.ErrGrantInvalid, "access grant does not belong to this client and device")
	case grant.Technician != c.session.Tech:
		return grant, dev, denied(proto.ErrGrantInvalid, "access grant belongs to another technician")
	}
	grant = g.refresh(ctx, c, grant, input)
	if err := grant.Usable(now); err != nil {
		return grant, dev, denied(proto.ErrGrantInvalid, "access grant is "+err.Error())
	}
	// A change under a grant whose unlock has ended could only be refused at
	// its release, so it is refused now, as a device call under it would be.
	if grant.Unlock != "" {
		if cerr := g.unlockLive(ctx, grant, now); cerr != nil {
			return grant, dev, cerr
		}
	}
	if cerr := requireOp(s.op, nil)(grant); cerr != nil {
		return grant, dev, cerr
	}
	return grant, dev, nil
}

// submitted answers a submitted change with where it waits and what the model
// should tell the technician. Nothing in it suggests the model can approve.
func (g *Gateway) submitted(row model.ChangeApproval, e *audit.Entry) (*mcp.CallToolResult, *callError) {
	link := g.companionLink("c", row.ID)
	what := "change"
	if row.Op == proto.OpRollbackFileChange {
		what = "rollback"
	}
	msg := "The technician has already approved this " + what + ", and the relay is releasing it to the machine. Call change_status with this approval_id for the outcome."
	if row.State == model.ChangeAwaiting {
		msg = fmt.Sprintf("Nothing has been written. This %s is waiting for the technician's approval in %s, where they review the exact diff and approve or deny it with a passkey. "+
			"Tell the user it is waiting for them there. It is released to the machine only once they approve it, and the request lapses at %s. "+
			"Call change_status with this approval_id to follow it.", what, companionPlace(link), row.ExpiresAt.UTC().Format(time.RFC3339))
	}
	raw, err := json.Marshal(ChangeSubmission{ApprovalID: row.ID, State: row.State, Op: row.Op, PlanID: row.PlanID,
		ExpiresAt: row.ExpiresAt.UTC(), Link: link, Message: msg})
	if err != nil {
		return nil, failed(proto.ErrInternal, "could not encode the submission")
	}
	e.Bytes, e.SHA256 = int64(len(raw)), sha256Hex(raw)
	return jsonResult(raw), nil
}

// companionPlace names the companion, with the card's link when there is one.
func companionPlace(link string) string {
	if link == "" {
		return "the Keyhole companion"
	}
	return "the Keyhole companion (" + link + ")"
}

// newChangeNonce draws the part of a change approval's signed fields nobody
// can predict, so a passkey assertion made for one approval can never be
// presented for another.
func newChangeNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ----- change_status -----

// changeStatus answers change_status: the state of one of the caller's own
// change approvals, and the machine's result once it is applied. It reaches no
// machine and is audited like any tool call.
func (g *Gateway) changeStatus(ctx context.Context, c caller, id string, input json.RawMessage) *mcp.CallToolResult {
	unlock := g.budgets.lock(c.session.ID)
	defer unlock()
	began := time.Now()
	e := g.entry(c, ToolChangeStatus, input)
	if c.technician {
		e.Client = g.auditClient(ctx, c)
	}
	out, cerr := func() (*mcp.CallToolResult, *callError) {
		row, err := g.approvals.ChangeApproval(ctx, strings.TrimSpace(id))
		switch {
		// Another technician's change, and for a client-bound session another
		// client's, is indistinguishable from one that does not exist.
		case errors.Is(err, model.ErrNotFound) || (err == nil && (row.Technician != c.session.Tech || (!c.technician && row.Client != c.client.Slug))):
			return nil, denied(proto.ErrNotFound, "change approval not found")
		case err != nil:
			g.log.Error("gateway: change approval lookup failed", "approval", id, "err", err)
			return nil, failed(proto.ErrInternal, "the change approval could not be read")
		}
		client, cerr := g.admitClient(ctx, c, row.Client)
		if cerr != nil {
			return nil, cerr
		}
		e.Client, e.DeviceID, e.RequestID = client.Slug, row.Device, row.ID
		if state, _ := row.Due(g.now()); state == model.ChangeExpired {
			g.expireChange(ctx, row)
			row = g.storedChange(ctx, row)
		}
		link := ""
		if row.State == model.ChangeAwaiting {
			link = g.companionLink("c", row.ID)
		}
		raw, err := json.Marshal(ChangeStatus{ApprovalID: row.ID, State: row.State, Op: row.Op, Device: row.Device,
			AccessID: row.AccessID, PlanID: row.PlanID, RollbackID: row.RollbackID, RequestedAt: row.RequestedAt,
			ExpiresAt: row.ExpiresAt, DecidedAt: row.DecidedAt, CompletedAt: row.CompletedAt, Reason: row.Reason,
			ErrorCode: row.ErrorCode, Result: row.Result, Link: link, Message: changeMessage(row, link)})
		if err != nil {
			return nil, failed(proto.ErrInternal, "could not encode the change status")
		}
		e.Bytes, e.SHA256 = int64(len(raw)), sha256Hex(raw)
		return jsonResult(raw), nil
	}()
	e.DurationMS = time.Since(began).Milliseconds()
	return g.finish(ctx, c, &e, out, cerr)
}

// changeMessage says what a change approval's state means for the model.
func changeMessage(row model.ChangeApproval, link string) string {
	switch row.State {
	case model.ChangeAwaiting:
		return "Waiting for the technician's approval in " + companionPlace(link) + ". Nothing has been written; it is released to the machine only once they approve it."
	case model.ChangeApproved:
		msg := "The technician approved it, and the relay is releasing it to the machine."
		if row.ErrorCode != "" {
			msg += fmt.Sprintf(" The last attempt did not get through (%s: %s); the relay tries again, with the same request, until the approval lapses at %s.",
				row.ErrorCode, row.Reason, row.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return msg
	case model.ChangeApplied:
		return "The machine made the change; result is what it reported."
	case model.ChangeRefused:
		return fmt.Sprintf("It was refused (%s: %s), so nothing was written. Prepare the change again if it is still needed.", row.ErrorCode, row.Reason)
	case model.ChangeFailed:
		return fmt.Sprintf("It did not complete: it could not be delivered, or its outcome was lost (%s: %s). Check the file, for example with hash_file, before preparing the change again.",
			row.ErrorCode, row.Reason)
	case model.ChangeDenied:
		return "The technician denied it. Nothing was written."
	case model.ChangeExpired:
		return "Nobody approved it before it lapsed. Nothing was written; prepare and submit it again if it is still needed."
	}
	return ""
}

// ----- the gate -----

// ApproveChange is the technician's approval of one change, made in the
// companion on their sign-in. The gateway checks the approval signs exactly
// what the stored row says and names a live passkey of the row's technician,
// while the row still waits; it then records the approval, audits
// it, and releases the change. The approval is recorded and released, or
// refused; what the release did is on the returned row.
func (g *Gateway) ApproveChange(ctx context.Context, id string, approval proto.TechnicianApproval) (model.ChangeApproval, error) {
	if !g.technicianApproval() {
		return model.ChangeApproval{}, errGateOff
	}
	row, err := g.approvals.ChangeApproval(ctx, id)
	switch {
	// Another technician's change is indistinguishable from one that does not
	// exist.
	case errors.Is(err, model.ErrNotFound) || (err == nil && row.Technician != approval.Technician):
		return model.ChangeApproval{}, fmt.Errorf("gateway: change approval %q: %w", id, model.ErrNotFound)
	case err != nil:
		return model.ChangeApproval{}, err
	}
	now := g.now()
	switch {
	case row.State != model.ChangeAwaiting:
		return row, fmt.Errorf("gateway: change approval %s is %s: %w", id, row.State, model.ErrConflict)
	case !now.Before(row.ExpiresAt):
		return row, fmt.Errorf("gateway: change approval %s lapsed at %s: %w", id, row.ExpiresAt.UTC().Format(time.RFC3339), model.ErrExpired)
	}
	if err := g.checkApproval(ctx, row.Technician, row.Approval(), approval); err != nil {
		return row, err
	}
	var assertion []byte
	if approval.Assertion != nil {
		if assertion, err = json.Marshal(approval.Assertion); err != nil {
			return row, fmt.Errorf("gateway: change approval %s: assertion: %w", id, err)
		}
	}
	approved, err := g.approvals.UpdateChangeApprovalTx(ctx, id, func(c *model.ChangeApproval) error {
		switch {
		case !model.ChangeAdvance(c.State, model.ChangeApproved):
			return fmt.Errorf("gateway: change approval %s is %s: %w", id, c.State, model.ErrConflict)
		case !now.Before(c.ExpiresAt):
			return fmt.Errorf("gateway: change approval %s lapsed: %w", id, model.ErrExpired)
		case !c.Approval().SameSigned(approval): // what it approves never changes; this is belt and braces
			return fmt.Errorf("gateway: the approval does not sign change %s as stored: %w", id, model.ErrInvalid)
		}
		// DecidedAt is the signed approval's own time, so SignedApproval gives
		// the endpoint exactly what the companion verified.
		decided := approval.ApprovedAt
		c.State, c.DecidedAt, c.Credential, c.Assertion = model.ChangeApproved, &decided, approval.Credential, assertion
		c.Reason, c.ErrorCode = "", ""
		return nil
	})
	if err != nil {
		return approved, err
	}
	// The release must never write what the audit log cannot show was
	// approved, so an approval that cannot be recorded is not released.
	if err := g.auditChange(ctx, approved); err != nil {
		g.log.Error("gateway: a change approval could not be audited; it is not released", "approval", id, "err", err)
		completed := g.now().UTC()
		return g.recordChangeOutcome(ctx, approved, model.ChangeFailed, func(c *model.ChangeApproval) {
			c.ErrorCode, c.Reason, c.CompletedAt = proto.ErrAuditFailed, "the approval could not be recorded in the audit log, so the change was not released", &completed
		}), nil
	}
	// Approving is using the unlock too, so the release does not find it idle.
	if a, err := g.access.Access(ctx, approved.AccessID); err == nil {
		g.touchUnlock(ctx, a.Unlock)
	}
	// The release runs to its end even if the technician's browser goes away:
	// the approval is given, and a release cut short would only be retried.
	rctx := context.WithoutCancel(ctx)
	done, ok := changeReleases.hold(id)
	if !ok {
		// The reconcile loop is releasing it already; report what that does.
		select {
		case <-done:
		case <-ctx.Done():
		}
		return g.storedChange(rctx, approved), nil
	}
	defer changeReleases.drop(id)
	return g.releaseChange(rctx, approved, false), nil
}

// DenyChange is the technician's refusal of one change. Denying reduces
// authority, so it needs only the technician's companion sign-in; credential
// is the passkey that sign-in used, recorded as who denied it.
func (g *Gateway) DenyChange(ctx context.Context, id, technician, credential string) (model.ChangeApproval, error) {
	if !g.technicianApproval() {
		return model.ChangeApproval{}, errGateOff
	}
	row, err := g.approvals.ChangeApproval(ctx, id)
	switch {
	case errors.Is(err, model.ErrNotFound) || (err == nil && row.Technician != technician):
		return model.ChangeApproval{}, fmt.Errorf("gateway: change approval %q: %w", id, model.ErrNotFound)
	case err != nil:
		return model.ChangeApproval{}, err
	}
	decided := g.now().UTC()
	return g.settleChange(ctx, id, model.ChangeDenied, func(c *model.ChangeApproval) error {
		c.Credential, c.DecidedAt, c.Reason = credential, &decided, model.ReasonDenied
		return nil
	})
}

// ----- the release -----

// changeReleases holds the change approvals being released right now. A
// release and a retry of the same approval must never run at once: each would
// record an outcome, and the second could record refused or failed over a
// change the first applied. Approval IDs are unique, so one set serves every
// gateway in the process.
var changeReleases = releaseSlots{held: map[string]chan struct{}{}}

type releaseSlots struct {
	mu   sync.Mutex
	held map[string]chan struct{}
}

// hold claims id's slot. If another release holds it, ok is false and done
// closes when that release ends.
func (s *releaseSlots) hold(id string) (done <-chan struct{}, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, busy := s.held[id]; busy {
		return ch, false
	}
	s.held[id] = make(chan struct{})
	return nil, true
}

func (s *releaseSlots) drop(id string) {
	s.mu.Lock()
	ch := s.held[id]
	delete(s.held, id)
	s.mu.Unlock()
	close(ch)
}

// releaseInput is what a release's audit entry records as its arguments.
type releaseInput struct {
	ApprovalID string `json:"approval_id"`
	PlanID     string `json:"plan_id"`
	Op         string `json:"op"`
	RollbackID string `json:"rollback_id,omitempty"`
}

// releaseChange runs an approved change on its endpoint, as the session that
// submitted it and with the signed approval and the approval's own request ID,
// and records the outcome. The caller holds the change's release slot. retry
// says an earlier release may have reached the endpoint without the relay
// learning what it did.
//
// Applied is recorded when the machine answered with a result; refused when
// the first release was refused, by the relay or the machine, so nothing was
// written. A release that did not get through leaves the change approved for
// the reconcile loop to release again. A retry that is refused is recorded as
// failed, not refused: an earlier attempt may have been applied.
func (g *Gateway) releaseChange(ctx context.Context, row model.ChangeApproval, retry bool) model.ChangeApproval {
	signed, err := row.SignedApproval()
	if err != nil {
		g.log.Error("gateway: an approved change carries no approval; it is not released", "approval", row.ID, "err", err)
		completed := g.now().UTC()
		return g.recordChangeOutcome(ctx, row, model.ChangeFailed, func(c *model.ChangeApproval) {
			c.ErrorCode, c.Reason, c.CompletedAt = proto.ErrInternal, "the stored approval could not be read, so the change was not released", &completed
		})
	}
	input, _ := json.Marshal(releaseInput{ApprovalID: row.ID, PlanID: row.PlanID, Op: row.Op, RollbackID: row.RollbackID})
	var args any = proto.ApplyFileChangeArgs{PlanID: row.PlanID, PlanDigest: row.PlanDigest, Approval: &signed}
	if row.Op == proto.OpRollbackFileChange {
		args = proto.RollbackFileChangeArgs{PlanID: row.PlanID, RollbackID: row.RollbackID, Approval: &signed}
	}
	var resp *proto.Response
	oc := opCall{tool: row.Op, device: row.Device, accessID: row.AccessID, requestID: row.RequestID, args: args, input: input,
		before: requireOp(row.Op, nil),
		// The machine answered and its answer passed the integrity check: the
		// change is made, whatever the bookkeeping after it does.
		render: func(d model.Device, r *proto.Response) (*mcp.CallToolResult, error) {
			resp = r
			return renderJSON(d, r)
		},
		after: func(a model.AccessRequest, _ *proto.Response) *callError {
			if row.Op == proto.OpApplyFileChange {
				g.spendPlan(ctx, a.ID, row.PlanDigest)
			}
			return nil
		},
	}
	c, cerr := g.changeReleaseCaller(ctx, row)
	cerr = g.runChangeRelease(ctx, c, row, oc, cerr)

	completed := g.now().UTC()
	if resp != nil {
		return g.recordChangeOutcome(ctx, row, model.ChangeApplied, func(x *model.ChangeApproval) {
			x.Result, x.CompletedAt, x.ErrorCode, x.Reason = resp.Result, &completed, "", ""
		})
	}
	if cerr == nil { // unreachable: a call without a result has an error
		cerr = failed(proto.ErrInternal, "the release produced neither a result nor an error")
	}
	switch {
	case retryableRelease(cerr.code):
		return g.noteReleaseAttempt(ctx, row, cerr)
	case !retry:
		return g.recordChangeOutcome(ctx, row, model.ChangeRefused, func(x *model.ChangeApproval) {
			x.ErrorCode, x.Reason, x.CompletedAt = cerr.code, cerr.msg, &completed
		})
	}
	return g.recordChangeOutcome(ctx, row, model.ChangeFailed, func(x *model.ChangeApproval) {
		x.ErrorCode, x.CompletedAt = cerr.code, &completed
		x.Reason = cerr.msg + "; an earlier release may have reached the machine, so whether it was applied is unknown"
	})
}

// runChangeRelease is runOp for a release: one audited device call, whose
// error the release needs to decide the outcome. The entry goes to the
// change's client, whoever the caller is. cerr is a refusal found while
// building the caller; the call is audited either way.
func (g *Gateway) runChangeRelease(ctx context.Context, c caller, row model.ChangeApproval, oc opCall, cerr *callError) *callError {
	unlock := g.budgets.lock(c.session.ID)
	defer unlock()
	began := time.Now()
	e := g.entry(c, oc.tool, oc.input)
	e.Client, e.DeviceID, e.RequestID = row.Client, row.Device, row.RequestID
	var out *mcp.CallToolResult
	if cerr == nil {
		out, cerr = g.doOp(ctx, c, oc, &e)
	}
	e.DurationMS = time.Since(began).Milliseconds()
	g.finish(ctx, c, &e, out, cerr)
	return cerr
}

// submitterSessions is the part of the relay store that finds an MCP session
// by ID. model.Directory does not require it; where the directory has it, a
// release refuses a client-bound session that has been revoked since it
// submitted.
type submitterSessions interface {
	Session(ctx context.Context, id string) (model.Session, error)
}

// changeReleaseCaller is who a release runs as: the session that submitted
// the change. A "ses_" session is a legacy client-bound caller, still bound to
// the change's client; anything else is a technician identity, whose client
// ACL doOp checks again. The session lives as long as the relay keeps
// releasing the approval, which is until the endpoint would refuse it anyway
// (see ChangeApproval.Due), so a release is never refused for outliving the
// MCP session that asked for it: the technician's passkey approved it since.
func (g *Gateway) changeReleaseCaller(ctx context.Context, row model.ChangeApproval) (caller, *callError) {
	s := model.Session{ID: row.Session, Tech: row.Technician, ExpiresAt: row.ExpiresAt.Add(proto.ApprovalClockSkew)}
	if !strings.HasPrefix(row.Session, model.PrefixSession+"_") {
		return caller{session: s, technician: true}, nil
	}
	s.Client = row.Client
	c := caller{session: s, client: model.Client{Slug: row.Client}}
	if sessions, ok := g.dir.(submitterSessions); ok {
		stored, err := sessions.Session(ctx, row.Session)
		switch {
		case errors.Is(err, model.ErrNotFound):
			return c, denied(proto.ErrUnauthorized, "the session that submitted this change no longer exists")
		case err != nil:
			g.log.Error("gateway: session lookup failed", "session", row.Session, "err", err)
			return c, failed(proto.ErrInternal, "the session that submitted this change could not be read")
		case stored.RevokedAt != nil:
			return c, denied(proto.ErrUnauthorized, "the session that submitted this change has been revoked")
		case stored.Client != row.Client || stored.Tech != row.Technician:
			return c, denied(proto.ErrUnauthorized, "the session that submitted this change belongs to another client or technician")
		}
	}
	client, err := g.dir.Client(ctx, row.Client)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return c, denied(proto.ErrUnauthorized, "client not found or not authorized")
	case err != nil:
		g.log.Error("gateway: client lookup failed", "client", row.Client, "err", err)
		return c, failed(proto.ErrInternal, "client lookup failed")
	}
	c.client = client
	return c, nil
}

// retryableRelease reports whether a release that ended with code may yet get
// through, so the change stays approved and the reconcile loop releases it
// again, with the same request ID: the machine was unreachable or busy, the
// answer was lost or unreadable, another change was in progress there, or the
// person at the machine has not yet approved the plan. Repeating a release is
// safe because the endpoint answers a request ID it has applied with its first
// result, and the approval's expiry bounds the retries.
func retryableRelease(code string) bool {
	switch code {
	case proto.ErrDeviceOffline, proto.ErrTimeout, proto.ErrInternal, proto.ErrIO, proto.ErrBusy,
		proto.ErrConflict, proto.ErrConsentRequired:
		return true
	}
	return false
}

// noteReleaseAttempt records why a release did not get through, for
// change_status, and leaves the change approved.
func (g *Gateway) noteReleaseAttempt(ctx context.Context, row model.ChangeApproval, cerr *callError) model.ChangeApproval {
	stored, err := g.approvals.UpdateChangeApprovalTx(ctx, row.ID, func(c *model.ChangeApproval) error {
		if c.State != model.ChangeApproved {
			return fmt.Errorf("gateway: change approval %s is %s: %w", c.ID, c.State, model.ErrConflict)
		}
		c.ErrorCode, c.Reason = cerr.code, cerr.msg
		return nil
	})
	if err != nil {
		g.log.Error("gateway: could not record a release attempt", "approval", row.ID, "err", err)
		if stored.ID == "" {
			return row
		}
	}
	return stored
}

// recordChangeOutcome records how a change ended and audits it, logging what
// cannot be stored: the outcome already happened.
func (g *Gateway) recordChangeOutcome(ctx context.Context, row model.ChangeApproval, state string, update func(*model.ChangeApproval)) model.ChangeApproval {
	stored, err := g.settleChange(ctx, row.ID, state, func(c *model.ChangeApproval) error {
		update(c)
		return nil
	})
	if err != nil {
		g.log.Error("gateway: could not record a change's outcome", "approval", row.ID, "state", state, "err", err)
		if stored.ID == "" {
			return row
		}
	}
	return stored
}

// spendPlan clears the plan digest a grant carries once that plan is applied,
// as applyFileChange does, unless a later prepare has replaced it.
func (g *Gateway) spendPlan(ctx context.Context, accessID, digest string) {
	_, err := g.access.UpdateAccessTx(ctx, accessID, func(a *model.AccessRequest) error {
		if a.PlanDigest != digest {
			return fmt.Errorf("access %s carries another plan: %w", accessID, model.ErrConflict)
		}
		a.PlanDigest = ""
		return nil
	})
	if err != nil && !errors.Is(err, model.ErrConflict) {
		g.log.Error("gateway: could not clear an applied plan from its grant", "access", accessID, "err", err)
	}
}

// ----- transitions and their audit -----

// settleChange moves one change approval to state against the row as it is
// stored now, under ChangeAdvance, and audits the move. update may refuse by
// returning an error wrapping model.ErrConflict. An audit failure is logged:
// the move stands, as every other recorded transition's does.
func (g *Gateway) settleChange(ctx context.Context, id, state string, update func(*model.ChangeApproval) error) (model.ChangeApproval, error) {
	stored, err := g.approvals.UpdateChangeApprovalTx(ctx, id, func(c *model.ChangeApproval) error {
		if !model.ChangeAdvance(c.State, state) {
			return fmt.Errorf("gateway: change approval %s is %s and cannot become %s: %w", id, c.State, state, model.ErrConflict)
		}
		if update != nil {
			if err := update(c); err != nil {
				return err
			}
		}
		c.State = state
		return nil
	})
	if err != nil {
		return stored, err
	}
	if err := g.auditChange(ctx, stored); err != nil {
		g.log.Error("gateway: a change approval's transition could not be audited", "approval", id, "state", state, "err", err)
	}
	return stored, nil
}

// changeAudit is the args of a change approval's audit entries.
type changeAudit struct {
	Source     string `json:"source"`
	Op         string `json:"op"`
	PlanID     string `json:"plan_id"`
	PlanDigest string `json:"plan_digest"`
	Credential string `json:"credential"`
	Reason     string `json:"reason"`
}

// auditChange records a change approval as it now stands in its client's
// chain: tool change.<state>, request ID the approval's ID, as the technician
// and session that submitted it. The passkey's credential ID is recorded; its
// assertion never is.
func (g *Gateway) auditChange(ctx context.Context, row model.ChangeApproval) error {
	args, err := json.Marshal(changeAudit{Source: "technician", Op: row.Op, PlanID: row.PlanID, PlanDigest: row.PlanDigest,
		Credential: row.Credential, Reason: row.Reason})
	if err != nil {
		return fmt.Errorf("audit change: %w", err)
	}
	result := audit.ResultOK
	switch row.State {
	case model.ChangeRefused, model.ChangeDenied, model.ChangeExpired:
		result = audit.ResultDenied
	case model.ChangeFailed:
		result = audit.ResultError
	}
	e := audit.Entry{Kind: audit.KindConsent, Client: row.Client, DeviceID: row.Device, Tech: row.Technician,
		SessionID: row.Session, RequestID: row.ID, Tool: "change." + row.State, Args: args, Result: result,
		ErrorCode: row.ErrorCode, ErrorMessage: row.Reason}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := g.audit.Append(actx, &e); err != nil {
		return fmt.Errorf("audit change: %w", err)
	}
	return nil
}

// storedChange is row as it is stored now, or row itself if it cannot be read.
func (g *Gateway) storedChange(ctx context.Context, row model.ChangeApproval) model.ChangeApproval {
	if stored, err := g.approvals.ChangeApproval(ctx, row.ID); err == nil {
		return stored
	}
	return row
}

// ----- reconcile -----

// reconcileChanges expires unanswered change approvals, retries releases
// whose outcome was lost, and purges plan records nobody needs.
func (g *Gateway) reconcileChanges(ctx context.Context) {
	if !g.technicianApproval() {
		return
	}
	open, err := g.approvals.ChangeApprovalsOpen(ctx)
	if err != nil {
		g.log.Error("gateway: could not list open change approvals", "err", err)
	}
	for _, row := range open {
		if ctx.Err() != nil {
			return
		}
		switch row.State {
		case model.ChangeAwaiting:
			g.expireChange(ctx, row)
		case model.ChangeApproved:
			g.retryChangeRelease(ctx, row.ID)
		}
	}
	if n, err := g.approvals.PurgeApprovals(ctx, g.now().Add(-model.ApprovalRetention)); err != nil {
		g.log.Error("gateway: could not purge technician approval records", "err", err)
	} else if n > 0 {
		g.log.Info("gateway: purged technician approval records", "rows", n)
	}
}

// expireChange ends a change approval nobody answered before its deadline.
func (g *Gateway) expireChange(ctx context.Context, row model.ChangeApproval) {
	now := g.now()
	if state, _ := row.Due(now); state != model.ChangeExpired {
		return
	}
	_, err := g.settleChange(ctx, row.ID, model.ChangeExpired, func(c *model.ChangeApproval) error {
		state, reason := c.Due(now)
		if state != model.ChangeExpired {
			return fmt.Errorf("gateway: change approval %s is not due: %w", c.ID, model.ErrConflict)
		}
		c.Reason = reason
		return nil
	})
	if err != nil && !errors.Is(err, model.ErrConflict) {
		g.log.Error("gateway: could not expire a change approval", "approval", row.ID, "err", err)
	}
}

// retryChangeRelease releases an approved change whose outcome the relay never
// learned, again and with the same request ID, or records it failed once its
// approval has lapsed at the endpoint too. A change being released right now
// is left to that release.
func (g *Gateway) retryChangeRelease(ctx context.Context, id string) {
	if _, ok := changeReleases.hold(id); !ok {
		return
	}
	defer changeReleases.drop(id)
	// Read it again under the slot: a release the listing saw may have
	// finished since.
	row, err := g.approvals.ChangeApproval(ctx, id)
	if err != nil || row.State != model.ChangeApproved {
		return
	}
	now := g.now()
	if state, reason := row.Due(now); state == model.ChangeFailed {
		completed := now.UTC()
		g.recordChangeOutcome(ctx, row, model.ChangeFailed, func(c *model.ChangeApproval) {
			c.Reason, c.CompletedAt = reason, &completed
		})
		return
	}
	g.releaseChange(ctx, row, true)
}
