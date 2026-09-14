package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient"
	"github.com/mrgyatso/keyhole/internal/agent"
	"github.com/mrgyatso/keyhole/internal/agent/consentscript"
	"github.com/mrgyatso/keyhole/internal/agent/hostinfo"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/fstools"
	"github.com/mrgyatso/keyhole/internal/gateway"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/natsauth/natsauthtest"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/redact"
	"github.com/mrgyatso/keyhole/internal/relay"
	"github.com/mrgyatso/keyhole/internal/store"
)

// Technician approval end to end (Slice 6): a real relay and gateway with the
// approval store on, and a real agent whose consent is RoutedConsent. The
// companion's passkey ceremony is covered by internal/companion's tests; here
// the approvals the companion would hand the gateway are built the same way
// and given to its ApprovalGate directly, so everything from the gate to the
// endpoint's disk is the production path.

const (
	approvalTech = "e2e-tech"
	approvalCred = "cred-e2e"
)

type approvalEnv struct {
	t        *testing.T
	ctx      context.Context
	st       *store.Store
	gw       *gateway.Gateway
	aud      *audit.JetStreamStore
	session  *mcp.ClientSession
	script   *consentscript.Adapter // the endpoint's own consent window, for endpoint-consent mode
	deviceID string
	file     string // a change target the policy allows
	secret   string // a file under the same directory that the policy's Files filter excludes
}

func setupApproval(t *testing.T, endpointConsent bool) *approvalEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	op, err := natsauth.NewOperator("e2e-approval")
	check(t, err)
	ns := natsauthtest.StartServer(t, op)
	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	check(t, err)
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.DiscardHandler)
	conns := relay.NewConnManager(ns.ClientURL(), st, log)
	t.Cleanup(conns.Close)
	aud := audit.NewJetStreamStore(conns)
	gw, err := gateway.New(gateway.Config{Directory: st, Access: st, Approvals: st, CompanionURL: "https://companion.test",
		Conns: conns, Audit: aud})
	check(t, err)
	sys, err := op.NewSysUser("relay")
	check(t, err)
	srv, err := relay.New(relay.Config{Store: st, Conns: conns, Operator: op, SysCreds: sys, Audit: aud,
		AgentNATSURLs: []string{ns.ClientURL()}, MCP: gw.Handler(), CompanionURL: "https://companion.test", Logger: log})
	check(t, err)
	check(t, srv.Start(ctx))
	t.Cleanup(srv.Close)

	adminToken := model.NewSecret(model.SecretAdmin)
	check(t, st.SetAdminTokenHash(ctx, model.HashSecret(adminToken), time.Now()))
	pub := httptest.NewServer(srv.PublicHandler())
	t.Cleanup(pub.Close)
	priv := httptest.NewServer(srv.PrivateHandler())
	t.Cleanup(priv.Close)
	ac := adminclient.New(priv.URL, adminToken, "e2e-admin", nil)
	_, err = ac.CreateClient(ctx, adminapi.CreateClientRequest{Slug: "acme", Name: "ACME"})
	check(t, err)
	root, err := filepath.EvalSymlinks(t.TempDir())
	check(t, err)
	file, secret := filepath.Join(root, "app.conf"), filepath.Join(root, "secret.txt")
	check(t, os.WriteFile(file, []byte(cfg0), 0o600))
	check(t, os.WriteFile(secret, []byte("not for the agent\n"), 0o600))
	p, err := ac.GetPolicy(ctx, "acme")
	check(t, err)
	// The rule allows the directory but only .conf and .log files in it, so a
	// grant naming the whole directory must still not reach secret.txt.
	p.Allow[runtime.GOOS] = []proto.AllowRule{{ID: "scratch", Path: root, Files: []string{"*.conf", "*.log"}}}
	p.EndpointConsent = endpointConsent
	_, err = ac.PutPolicy(ctx, "acme", p)
	check(t, err)
	tok, err := ac.MintToken(ctx, "acme", adminapi.MintTokenRequest{})
	check(t, err)

	// The technician's passkey. The gateway checks the passkey's owner and that
	// it is live; the companion checks its signature.
	now := time.Now().UTC()
	link := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: approvalTech,
		Hash: model.HashSecret("e2e-link"), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	check(t, st.CreatePasskeyLink(ctx, link))
	check(t, st.UsePasskeyLink(ctx, link.ID, model.Passkey{CredentialID: approvalCred, Technician: approvalTech,
		PublicKey: []byte{1}, Algorithm: -7}, now))

	data := agent.DataDir(filepath.Join(t.TempDir(), "agent"))
	host := hostinfo.Info{Hostname: "acme-box", MachineID: "acme-machine", OS: runtime.GOOS, Arch: runtime.GOARCH}
	enrollment, err := agent.Enroll(ctx, agent.EnrollOptions{RelayURL: pub.URL, Token: tok.Secret, Org: "acme", DataDir: data, Host: host})
	check(t, err)
	red, err := redact.New()
	check(t, err)
	script := consentscript.New()
	x := fstools.New(fstools.Options{Redactor: red, ChangeDir: data.File(agent.ChangeSubdir)})
	runner, err := agent.NewRunner(agent.RunnerOptions{Enrollment: enrollment, CredsFile: data.CredsPath(),
		Executor: x, Host: host, Logger: log, GrantsFile: data.File("grants.json"),
		Consent: agent.RoutedConsent{Technician: agent.TechnicianConsent{Logger: log}, Endpoint: script}})
	check(t, err)
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(runCtx) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent shutdown timed out")
		}
	})
	for {
		d, e := st.Device(ctx, enrollment.DeviceID)
		if e == nil && d.Online(time.Now()) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("device did not become online")
		case <-time.After(10 * time.Millisecond):
		}
	}

	sess, err := ac.MintSession(ctx, "acme", adminapi.MintSessionRequest{Tech: approvalTech})
	check(t, err)
	mc := mcp.NewClient(&mcp.Implementation{Name: "approval", Version: "test"}, nil)
	cs, err := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: priv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer(sess.Bearer)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	check(t, err)
	t.Cleanup(func() { cs.Close() })
	return &approvalEnv{t: t, ctx: ctx, st: st, gw: gw, aud: aud, session: cs, script: script,
		deviceID: enrollment.DeviceID, file: file, secret: secret}
}

func (e *approvalEnv) call(tool string, args map[string]any) (string, bool) {
	e.t.Helper()
	result, err := e.session.CallTool(e.ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	check(e.t, err)
	var out strings.Builder
	for _, c := range result.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			out.WriteString(text.Text)
		}
	}
	return out.String(), result.IsError
}

// requestAccess asks for access and returns the stored request.
func (e *approvalEnv) requestAccess(purpose string, ops ...string) model.AccessRequest {
	e.t.Helper()
	args := map[string]any{"device": e.deviceID, "purpose": purpose}
	if len(ops) > 0 {
		args["operations"] = ops
	}
	text, bad := e.call(proto.OpRequestAccess, args)
	if bad {
		e.t.Fatalf("request_access: %s", text)
	}
	var out map[string]any // the stored request, with its access_id beside it
	check(e.t, json.Unmarshal([]byte(text), &out))
	id, _ := out["access_id"].(string)
	if id == "" {
		id, _ = out["id"].(string)
	}
	a, err := e.st.Access(e.ctx, id)
	check(e.t, err)
	return a
}

// access waits until the stored request is in one of want.
func (e *approvalEnv) access(id string, want ...string) model.AccessRequest {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		a, err := e.st.Access(e.ctx, id)
		check(e.t, err)
		for _, w := range want {
			if a.State == w {
				return a
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("access %s is %s (%s), want one of %v", id, a.State, a.Reason, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *approvalEnv) read(accessID, path string) (string, bool) {
	e.t.Helper()
	return e.call(proto.OpReadFile, map[string]any{"device": e.deviceID, "access_id": accessID, "path": path})
}

// approveUnlock does what the companion does once the technician's passkey
// has signed: its begin offers a nonce and an expiry, and the signed approval
// goes to the gate.
func (e *approvalEnv) approveUnlock(id string) model.Unlock {
	e.t.Helper()
	now := time.Now().UTC()
	u, err := e.st.UpdateUnlockTx(e.ctx, id, func(u *model.Unlock) error {
		expires := now.Add(u.Duration)
		u.Nonce, u.ExpiresAt = model.NewSecret("n"), &expires
		return nil
	})
	check(e.t, err)
	a := u.Approval()
	a.Credential, a.ApprovedAt, a.Assertion = approvalCred, now, &proto.PasskeyAssertion{CredentialID: approvalCred}
	got, err := e.gw.ApproveUnlock(e.ctx, id, a)
	check(e.t, err)
	return got
}

func (e *approvalEnv) approveChange(id string) model.ChangeApproval {
	e.t.Helper()
	c, err := e.st.ChangeApproval(e.ctx, id)
	check(e.t, err)
	a := c.Approval()
	a.Credential, a.ApprovedAt, a.Assertion = approvalCred, time.Now().UTC(), &proto.PasskeyAssertion{CredentialID: approvalCred}
	got, err := e.gw.ApproveChange(e.ctx, id, a)
	check(e.t, err)
	return got
}

// submitted is the change approval an apply or rollback created.
func (e *approvalEnv) submitted(accessID, planID, op string) model.ChangeApproval {
	e.t.Helper()
	c, err := e.st.ChangeApprovalFor(e.ctx, accessID, planID, op, model.ChangeAwaiting)
	if err != nil {
		e.t.Fatalf("no awaiting %s approval for plan %s: %v", op, planID, err)
	}
	return c
}

func (e *approvalEnv) prepare(accessID, content string) (planID, digest string) {
	e.t.Helper()
	text, bad := e.call(proto.OpPrepareFileChange, map[string]any{"device": e.deviceID, "access_id": accessID,
		"path": e.file, "content": content, "reason": "e2e"})
	if bad {
		e.t.Fatalf("prepare_file_change: %s", text)
	}
	return planFields(e.t, text)
}

func (e *approvalEnv) auditHas(match func(audit.Entry) bool) bool {
	e.t.Helper()
	found := false
	check(e.t, e.aud.Range(e.ctx, "acme", time.Time{}, time.Time{}, func(en audit.Entry) error {
		found = found || match(en)
		return nil
	}))
	return found
}

func TestTechnicianApprovalE2E(t *testing.T) {
	e := setupApproval(t, false)
	ctx := e.ctx

	// Nothing is unlocked, so the request waits for the technician and the
	// endpoint has not seen it: there is no grant to read under.
	first := e.requestAccess("ticket 42: vendor log errors")
	if first.State != model.AccessAwaitingUnlock {
		t.Fatalf("first request is %s, want %s", first.State, model.AccessAwaitingUnlock)
	}
	u, err := e.st.UnlockFor(ctx, approvalTech, "acme", model.UnlockAwaiting)
	check(t, err)
	if first.Unlock != u.ID {
		t.Fatalf("the request waits for %q, not the pending unlock %q", first.Unlock, u.ID)
	}
	if text, bad := e.read(first.ID, e.file); !bad {
		t.Fatalf("read before the unlock: %s", text)
	}

	// The technician unlocks the client. The waiting request reaches the
	// endpoint, which approves it on the technician's word.
	e.approveUnlock(u.ID)
	granted := e.access(first.ID, model.AccessApproved, model.AccessActive)
	if !strings.HasPrefix(granted.Approver, "technician "+approvalTech) || granted.Unlock != u.ID {
		t.Fatalf("granted = approver %q, unlock %q", granted.Approver, granted.Unlock)
	}

	// Reads work and stay inside the client's policy: the rule's Files filter
	// still hides secret.txt, though the grant names the whole directory.
	if text, bad := e.read(first.ID, e.file); bad || !strings.Contains(text, "retries=3") {
		t.Fatalf("read under the unlock: %s", text)
	}
	if text, bad := e.read(first.ID, e.secret); !bad {
		t.Fatalf("an auto-approved grant widened the client's policy: %s", text)
	}

	// A second request under the live unlock is granted at once.
	began := time.Now()
	second := e.requestAccess("ticket 42: fix the retry setting", proto.OpReadFile, proto.OpHashFile,
		proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange)
	second = e.access(second.ID, model.AccessApproved, model.AccessActive)
	if waited := time.Since(began); waited > 6*time.Second {
		t.Fatalf("a request under a live unlock took %s", waited)
	}
	if _, err := e.st.UnlockFor(ctx, approvalTech, "acme", model.UnlockAwaiting); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("a second request asked for another unlock: %v", err)
	}

	// prepare is a dry run: nothing written, nobody prompted, and the relay
	// keeps the plan for the change card.
	planID, digest := e.prepare(second.ID, cfg1)
	if onDisk(t, e.file) != cfg0 {
		t.Fatal("prepare wrote the file")
	}
	if _, err := e.st.ChangePlan(ctx, planID); err != nil {
		t.Fatalf("the relay kept no plan for the card: %v", err)
	}

	// apply submits the plan to the gate; nothing reaches the endpoint yet.
	if text, bad := e.call(proto.OpApplyFileChange, map[string]any{"device": e.deviceID, "access_id": second.ID,
		"plan_id": planID, "plan_digest": digest}); bad {
		t.Fatalf("apply_file_change: %s", text)
	}
	ca := e.submitted(second.ID, planID, proto.OpApplyFileChange)
	if onDisk(t, e.file) != cfg0 {
		t.Fatal("apply wrote before the technician approved")
	}

	// The technician approves: the change is released with the approval and
	// applied, and the audit entry of the apply names the approval.
	applied := e.approveChange(ca.ID)
	if applied.State != model.ChangeApplied || onDisk(t, e.file) != cfg1 {
		t.Fatalf("after approval: state %s (%s %s), file %q", applied.State, applied.ErrorCode, applied.Reason, onDisk(t, e.file))
	}
	if text, bad := e.call(gateway.ToolChangeStatus, map[string]any{"approval_id": ca.ID}); bad || !strings.Contains(text, model.ChangeApplied) {
		t.Fatalf("change_status: %s", text)
	}
	if !e.auditHas(func(en audit.Entry) bool {
		return en.Tool == proto.OpApplyFileChange && strings.Contains(string(en.Change), ca.ID)
	}) {
		t.Fatal("no audit entry of the apply names its approval")
	}

	// Undo goes through the gate as well.
	var res proto.ApplyFileChangeResult
	check(t, json.Unmarshal(applied.Result, &res))
	if text, bad := e.call(proto.OpRollbackFileChange, map[string]any{"device": e.deviceID, "access_id": second.ID,
		"plan_id": planID, "rollback_id": res.RollbackID}); bad {
		t.Fatalf("rollback_file_change: %s", text)
	}
	rb := e.submitted(second.ID, planID, proto.OpRollbackFileChange)
	if onDisk(t, e.file) != cfg1 {
		t.Fatal("rollback wrote before the technician approved")
	}
	if got := e.approveChange(rb.ID); got.State != model.ChangeApplied || onDisk(t, e.file) != cfg0 {
		t.Fatalf("after the approved rollback: %s, file %q", got.State, onDisk(t, e.file))
	}

	// A target that changed after prepare is refused at the endpoint, even
	// with the technician's approval.
	planID, digest = e.prepare(second.ID, cfg2)
	e.call(proto.OpApplyFileChange, map[string]any{"device": e.deviceID, "access_id": second.ID, "plan_id": planID, "plan_digest": digest})
	stale := e.submitted(second.ID, planID, proto.OpApplyFileChange)
	check(t, os.WriteFile(e.file, []byte(cfg3), 0o600)) // a third party edits it
	if got := e.approveChange(stale.ID); got.State != model.ChangeRefused || got.ErrorCode != proto.ErrStalePlan {
		t.Fatalf("approving a stale plan: %s %s", got.State, got.ErrorCode)
	}
	if onDisk(t, e.file) != cfg3 {
		t.Fatal("a stale plan overwrote a third party's change")
	}

	// A denied change writes nothing.
	planID, digest = e.prepare(second.ID, cfg1)
	e.call(proto.OpApplyFileChange, map[string]any{"device": e.deviceID, "access_id": second.ID, "plan_id": planID, "plan_digest": digest})
	denied := e.submitted(second.ID, planID, proto.OpApplyFileChange)
	if got, err := e.gw.DenyChange(ctx, denied.ID, approvalTech, approvalCred); err != nil || got.State != model.ChangeDenied {
		t.Fatalf("DenyChange = %+v, %v", got, err)
	}
	if onDisk(t, e.file) != cfg3 {
		t.Fatal("a denied change was written")
	}

	// Lock ends every grant the unlock made, at once.
	if _, err := e.gw.Lock(ctx, u.ID, approvalTech, model.ReasonLocked); err != nil {
		t.Fatal(err)
	}
	e.access(first.ID, model.AccessTerminated)
	e.access(second.ID, model.AccessTerminated)
	if text, bad := e.read(second.ID, e.file); !bad {
		t.Fatalf("read after Lock: %s", text)
	}
}

func TestEndpointConsentModeAsksThePersonAtTheMachineToo(t *testing.T) {
	e := setupApproval(t, true)
	req := e.requestAccess("ticket 7")
	u, err := e.st.UnlockFor(e.ctx, approvalTech, "acme", model.UnlockAwaiting)
	check(t, err)
	e.approveUnlock(u.ID)
	// After the technician, the person at the machine is asked.
	waitCtx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	defer cancel()
	c, err := e.script.Wait(waitCtx, req.ID)
	check(t, err)
	e.access(req.ID, model.AccessAwaiting)
	c.Approve(`ACME\person`)
	granted := e.access(req.ID, model.AccessApproved, model.AccessActive)
	if !granted.EndpointConsent || granted.Approver != `ACME\person` {
		t.Fatalf("granted = %+v", granted)
	}
	if text, bad := e.read(req.ID, e.file); bad {
		t.Fatalf("read after both approvals: %s", text)
	}
}
