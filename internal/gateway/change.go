package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Structured remediation, relay side. Every one of these tools runs under an
// approved grant whose operations include the op; the relay checks the grant,
// the recorded plan digest and the client kill switch, and the endpoint checks
// all of it again against the plan it actually holds. The endpoint's answer is
// the authoritative one.

// PrepareFileChangeInput is the input of prepare_file_change.
type PrepareFileChangeInput struct {
	Device        string `json:"device" jsonschema:"The machine to change: its device ID (dev_...) or its hostname, as shown by list_devices."`
	AccessID      string `json:"access_id" jsonschema:"Approved access request ID whose operations include prepare_file_change."`
	Path          string `json:"path" jsonschema:"Absolute path of the existing file to change, in the machine's own syntax."`
	Content       string `json:"content,omitempty" jsonschema:"The file's complete new text. Send the whole file, not a patch."`
	ContentBase64 string `json:"content_base64,omitempty" jsonschema:"The file's complete new bytes, base64 encoded. Requires mode=binary."`
	Mode          string `json:"mode,omitempty" jsonschema:"text (default) or binary."`
	ExpectSHA256  string `json:"expect_sha256,omitempty" jsonschema:"Refuse unless the file currently has this SHA-256, e.g. the one hash_file returned."`
	Reason        string `json:"reason,omitempty" jsonschema:"What this change fixes. The person at the machine reads it beside the diff."`
}

// ApplyFileChangeInput is the input of apply_file_change.
type ApplyFileChangeInput struct {
	Device     string `json:"device" jsonschema:"The machine the plan was prepared on."`
	AccessID   string `json:"access_id" jsonschema:"The access grant the plan was prepared under."`
	PlanID     string `json:"plan_id" jsonschema:"Plan ID returned by prepare_file_change."`
	PlanDigest string `json:"plan_digest" jsonschema:"Plan digest returned by prepare_file_change. It must match the reviewed plan exactly."`
}

// RollbackFileChangeInput is the input of rollback_file_change.
type RollbackFileChangeInput struct {
	Device     string `json:"device" jsonschema:"The machine the change was applied on."`
	AccessID   string `json:"access_id" jsonschema:"An access grant whose operations include rollback_file_change."`
	PlanID     string `json:"plan_id" jsonschema:"Plan ID of the applied change."`
	RollbackID string `json:"rollback_id,omitempty" jsonschema:"Rollback ID returned by apply_file_change. Omit to use the plan's own copy."`
}

// ServiceQueryInput is the input of service_query.
type ServiceQueryInput struct {
	Device   string `json:"device" jsonschema:"The machine to query."`
	AccessID string `json:"access_id" jsonschema:"Approved access request ID whose operations include service_query."`
	Name     string `json:"name" jsonschema:"Service name, e.g. VendorService on Windows or vendor.service on Linux. Only services the client's policy lists can be named."`
}

// ServiceRestartInput is the input of service_restart.
type ServiceRestartInput struct {
	Device   string `json:"device" jsonschema:"The machine whose service to restart."`
	AccessID string `json:"access_id" jsonschema:"Approved access request ID whose operations include service_restart."`
	Name     string `json:"name" jsonschema:"Service name. Only services the client's policy lists can be restarted, and never Keyhole's own or the machine's security services."`
}

// changeToolText is what the file change tools tell the model about
// themselves.
type changeToolText struct{ prepare, apply, rollback string }

// legacyChangeTools describe the Slice 5 flow, where the person at the machine
// reviews each plan.
var legacyChangeTools = changeToolText{
	prepare:  "Propose replacing a file's whole content on a machine. The machine reads the file, records what it is, and returns a diff and a plan digest. Where the machine has a Keyhole consent window, the person there is shown the diff and must approve it; apply_file_change answers consent_required until they do. Nothing is written until apply_file_change quotes that plan and digest back.",
	apply:    "Apply a prepared change. The machine refuses unless the person there approved this plan (where it asks them) and the file is still exactly what the plan reviewed; it saves a rollback copy and replaces the file atomically, then returns the hashes before and after.",
	rollback: "Restore the copy an apply saved. The machine refuses if the file no longer holds what that apply wrote, so a later change by someone else is never discarded.",
}

// gatedChangeTools describe the change gate: the technician approves each
// change in the companion. None of them suggests the model can approve.
var gatedChangeTools = changeToolText{
	prepare: "Propose replacing a file's whole content on a machine. This is a dry run that prompts nobody: the machine reads the file, records what it is, stages the new content without touching the file, and returns a diff and a plan digest, so you can prepare, review and prepare again. Nothing is written until apply_file_change submits the plan and the technician approves it in the Keyhole companion.",
	apply:   "Submit a prepared plan for the technician's approval. This contacts no machine and writes nothing: it answers awaiting_approval with an approval ID and a link to the Keyhole companion, where the technician reviews the exact diff and approves or denies it with a passkey. Only their approval releases the change to the machine, which checks again that the file is still what the plan reviewed before replacing it and saving a rollback copy. Poll change_status for the outcome.",
	rollback: "Submit restoring the copy an apply saved, for the technician's approval in the Keyhole companion, exactly like apply_file_change: nothing is written until they approve it, and change_status reports the outcome, including the rollback_id of an applied change. " +
		"The machine refuses if the file no longer holds what that apply wrote, so a later change by someone else is never discarded.",
}

// addChangeTools registers the structured remediation tools. They are
// deliberately separate from the read tools: each one is marked as writing,
// and none of them can run without an access grant.
func (g *Gateway) addChangeTools(srv *mcp.Server, c caller) {
	yes, no := true, false
	prep := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &no, IdempotentHint: true}
	write := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &yes, IdempotentHint: true}
	text := legacyChangeTools
	if g.technicianApproval() {
		text = gatedChangeTools
	}

	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpPrepareFileChange, Title: "Prepare file change", Annotations: prep, Description: text.prepare},
		func(ctx context.Context, req *mcp.CallToolRequest, in PrepareFileChangeInput) (*mcp.CallToolResult, any, error) {
			return g.prepareFileChange(ctx, c, in, rawArgs(req)), nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpApplyFileChange, Title: "Apply file change", Annotations: write, Description: text.apply},
		func(ctx context.Context, req *mcp.CallToolRequest, in ApplyFileChangeInput) (*mcp.CallToolResult, any, error) {
			return g.applyFileChange(ctx, c, in, rawArgs(req)), nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpRollbackFileChange, Title: "Roll back file change", Annotations: write, Description: text.rollback},
		func(ctx context.Context, req *mcp.CallToolRequest, in RollbackFileChangeInput) (*mcp.CallToolResult, any, error) {
			return g.rollbackFileChange(ctx, c, in, rawArgs(req)), nil, nil
		})

	if g.technicianApproval() {
		ro := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, DestructiveHint: &no}
		mcp.AddTool(srv, &mcp.Tool{Name: ToolChangeStatus, Title: "Change status", Annotations: ro,
			Description: "Get the state of a change submitted with apply_file_change or rollback_file_change: awaiting_approval (waiting for the technician in the Keyhole companion), approved (being released to the machine), applied (with the machine's result), refused (nothing was written), failed (not delivered, or its outcome was lost), denied or expired."},
			func(ctx context.Context, req *mcp.CallToolRequest, in ChangeStatusInput) (*mcp.CallToolResult, any, error) {
				return g.changeStatus(ctx, c, in.ApprovalID, rawArgs(req)), nil, nil
			})
	}

	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpServiceQuery, Title: "Service state", Annotations: prep,
		Description: "Report the state, start type and process ID of one service the client's policy allows Keyhole to see."},
		func(ctx context.Context, req *mcp.CallToolRequest, in ServiceQueryInput) (*mcp.CallToolResult, any, error) {
			return g.runOp(ctx, c, opCall{tool: proto.OpServiceQuery, device: in.Device, accessID: in.AccessID,
				input: rawArgs(req), args: proto.ServiceQueryArgs{Name: in.Name}, render: renderJSON,
				before: requireOp(proto.OpServiceQuery, nil)}), nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: proto.OpServiceRestart, Title: "Restart service", Annotations: write,
		Description: "Stop and start one service the client's policy allows. There is no command line: only a service name, and never Keyhole's own service or the machine's security, identity or remote-access services."},
		func(ctx context.Context, req *mcp.CallToolRequest, in ServiceRestartInput) (*mcp.CallToolResult, any, error) {
			return g.runOp(ctx, c, opCall{tool: proto.OpServiceRestart, device: in.Device, accessID: in.AccessID,
				input: rawArgs(req), args: proto.ServiceRestartArgs{Name: in.Name}, render: renderJSON,
				before: requireOp(proto.OpServiceRestart, nil)}), nil, nil
		})
}

// prepareFileChange runs the prepare and records the resulting plan digest on
// the grant. That record is what apply_file_change is checked against, so a
// plan that cannot be recorded is reported as unusable rather than silently
// left staged. Under technician approval the relay also keeps its own copy of
// the plan, diff included, for the technician's change card.
func (g *Gateway) prepareFileChange(ctx context.Context, c caller, in PrepareFileChangeInput, input json.RawMessage) *mcp.CallToolResult {
	args := proto.PrepareFileChangeArgs{Path: in.Path, Mode: in.Mode, Content: in.Content,
		ContentBase64: in.ContentBase64, ExpectSHA256: in.ExpectSHA256, Reason: in.Reason}
	render := renderPlan
	if g.technicianApproval() {
		render = renderGatedPlan
	}
	return g.runOp(ctx, c, opCall{
		tool: proto.OpPrepareFileChange, device: in.Device, accessID: in.AccessID, input: input, args: args,
		render: render,
		before: requireOp(proto.OpPrepareFileChange, nil),
		after: func(a model.AccessRequest, resp *proto.Response) *callError {
			var res proto.PrepareFileChangeResult
			if err := json.Unmarshal(resp.Result, &res); err != nil || res.PlanDigest == "" {
				return failed(proto.ErrInternal, "the machine returned a change plan the relay could not read")
			}
			if g.technicianApproval() {
				if cerr := g.recordChangePlan(ctx, a, res.ChangePlan); cerr != nil {
					return cerr
				}
			}
			return g.recordPlan(ctx, a.ID, res.PlanDigest)
		},
	})
}

// applyFileChange refuses before the machine is contacted unless the grant
// carries exactly this plan digest. The endpoint holds the plan itself and
// checks again; this check keeps a mismatched apply off the wire. Under
// technician approval it contacts no machine at all: it submits the plan to
// the change gate.
func (g *Gateway) applyFileChange(ctx context.Context, c caller, in ApplyFileChangeInput, input json.RawMessage) *mcp.CallToolResult {
	if g.technicianApproval() {
		return g.submitChange(ctx, c, changeSubmission{op: proto.OpApplyFileChange, device: in.Device, accessID: in.AccessID,
			planID: in.PlanID, planDigest: in.PlanDigest}, input)
	}
	args := proto.ApplyFileChangeArgs{PlanID: in.PlanID, PlanDigest: in.PlanDigest}
	return g.runOp(ctx, c, opCall{
		tool: proto.OpApplyFileChange, device: in.Device, accessID: in.AccessID, input: input, args: args,
		render: renderJSON,
		before: requireOp(proto.OpApplyFileChange, func(a model.AccessRequest) *callError {
			switch {
			case strings.TrimSpace(in.PlanID) == "" || strings.TrimSpace(in.PlanDigest) == "":
				return denied(proto.ErrBadRequest, "plan_id and plan_digest come from prepare_file_change and are both required")
			case a.PlanDigest == "":
				return denied(proto.ErrGrantInvalid, "this access grant has no prepared change; call prepare_file_change first")
			case a.PlanDigest != in.PlanDigest:
				return denied(proto.ErrGrantInvalid, "this access grant's approved plan has a different digest; prepare the change again and apply that plan")
			}
			return nil
		}),
		// The plan is spent once it is applied, so the grant stops carrying it.
		after: func(a model.AccessRequest, _ *proto.Response) *callError { return g.recordPlan(ctx, a.ID, "") },
	})
}

// rollbackFileChange restores the copy an apply saved. Rollback checks no
// review at the machine, so under technician approval it goes through the
// change gate exactly like an apply.
func (g *Gateway) rollbackFileChange(ctx context.Context, c caller, in RollbackFileChangeInput, input json.RawMessage) *mcp.CallToolResult {
	if g.technicianApproval() {
		return g.submitChange(ctx, c, changeSubmission{op: proto.OpRollbackFileChange, device: in.Device, accessID: in.AccessID,
			planID: in.PlanID, rollbackID: in.RollbackID}, input)
	}
	args := proto.RollbackFileChangeArgs{PlanID: in.PlanID, RollbackID: in.RollbackID}
	return g.runOp(ctx, c, opCall{tool: proto.OpRollbackFileChange, device: in.Device, accessID: in.AccessID,
		input: input, args: args, render: renderJSON,
		before: requireOp(proto.OpRollbackFileChange, func(model.AccessRequest) *callError {
			if strings.TrimSpace(in.PlanID) == "" {
				return denied(proto.ErrBadRequest, "plan_id is required; it is the plan apply_file_change applied")
			}
			return nil
		})})
}

// requireOp refuses a remediation call whose grant does not include the op,
// before the machine is contacted. The endpoint checks the same thing against
// its own live grant and has the final say; this is the relay doing its half.
func requireOp(op string, extra func(model.AccessRequest) *callError) func(model.AccessRequest) *callError {
	return func(a model.AccessRequest) *callError {
		if !slices.Contains(a.EffectiveOperations, op) {
			return denied(proto.ErrGrantInvalid, "this access grant does not include "+op+"; request access for it")
		}
		if extra != nil {
			return extra(a)
		}
		return nil
	}
}

// recordPlan stores (or clears) the plan digest this grant may apply. It
// re-reads the request so it never overwrites a state transition another step
// of the same call has just written.
func (g *Gateway) recordPlan(ctx context.Context, accessID, digest string) *callError {
	if g.access == nil {
		return failed(proto.ErrInternal, "consented access store is unavailable")
	}
	a, err := g.access.Access(ctx, accessID)
	if err != nil {
		return failed(proto.ErrInternal, "the access grant could not be read back")
	}
	if a.PlanDigest == digest {
		return nil
	}
	a.PlanDigest = digest
	if err := g.access.UpdateAccess(ctx, a); err != nil {
		return failed(proto.ErrInternal, "the change plan could not be recorded on the access grant, so it cannot be applied")
	}
	return nil
}

// renderPlan shows the plan's identity and hashes, then the diff inside the
// untrusted-data boundary: a diff is file content, and content from a client's
// machine is evidence, never instructions.
func renderPlan(d model.Device, r *proto.Response) (*mcp.CallToolResult, error) {
	return renderPlanText(d, r, false)
}

// renderGatedPlan is renderPlan under technician approval, where the next
// step is submitting the plan to the technician rather than applying it.
func renderGatedPlan(d model.Device, r *proto.Response) (*mcp.CallToolResult, error) {
	return renderPlanText(d, r, true)
}

func renderPlanText(d model.Device, r *proto.Response, gated bool) (*mcp.CallToolResult, error) {
	var res proto.PrepareFileChangeResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		return nil, err
	}
	var b strings.Builder
	review := ""
	if res.Review != "" {
		review = " | review: " + res.Review
	}
	fmt.Fprintf(&b, "device: %s | path: %s | plan: %s | digest: %s\nbefore: %s (%d bytes) | after: %s (%d bytes) | approved: %t%s | expires: %s | redactions: %d\n",
		deviceLabel(d), res.Before.Path, res.PlanID, res.PlanDigest,
		res.Before.SHA256, res.Before.Size, res.AfterSHA256, res.AfterSize, res.Approved, review,
		res.ExpiresAt.UTC().Format("15:04:05Z"), r.Meta.Redactions)
	switch {
	case gated && res.Review == "awaiting":
		b.WriteString("Nothing has been written: this was a dry run. The client's policy also asks the person at the machine, who is now being shown this diff and must approve it there. " +
			"To make the change, call apply_file_change with this plan ID and digest: it submits the plan for the technician's approval in the Keyhole companion, " +
			"and the change is released to the machine only once both have approved it.\n")
	case gated:
		b.WriteString("Nothing has been written: this was a dry run, and nobody has been asked anything. Review the diff; to make the change, call apply_file_change with this plan ID and digest, " +
			"which submits it for the technician's approval in the Keyhole companion. Nothing is written until they approve it there.\n")
	case res.Review == "awaiting":
		fmt.Fprintf(&b, "Nothing has been written. The person at the machine is now being shown this diff and must approve it there; "+
			"Windows asks them to confirm as an administrator. Until they do, apply_file_change answers %s. "+
			"Tell the user the change is waiting for approval at the machine, then call apply_file_change with this plan ID and digest.\n",
			proto.ErrConsentRequired)
	default:
		b.WriteString("Nothing has been written yet. Review the diff, then call apply_file_change with this plan ID and digest.\n")
	}
	if res.Binary {
		fmt.Fprintf(&b, "The change is binary, so there is no diff: %d bytes become %d bytes.", res.Before.Size, res.AfterSize)
		return textResult(b.String()), nil
	}
	if res.DiffTruncated {
		b.WriteString("The diff is longer than the review limit and is shown truncated.\n")
	}
	writeUntrusted(&b, d, res.Before.Path, res.Diff)
	return textResult(b.String()), nil
}

// changeOperations validates the operations an access request asks for. It
// defaults to read_file, refuses anything outside the known set, and makes
// apply imply prepare, since a plan can only be applied by the grant that
// prepared it.
func changeOperations(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return []string{proto.OpReadFile}, nil
	}
	known := proto.ChangeOperations()
	var ops []string
	for _, op := range requested {
		op = strings.TrimSpace(op)
		if !slices.Contains(known, op) {
			return nil, fmt.Errorf("%q is not an operation this endpoint offers; choose from %s", op, strings.Join(known, ", "))
		}
		if !slices.Contains(ops, op) {
			ops = append(ops, op)
		}
	}
	if slices.Contains(ops, proto.OpApplyFileChange) && !slices.Contains(ops, proto.OpPrepareFileChange) {
		ops = append(ops, proto.OpPrepareFileChange)
	}
	return ops, nil
}
