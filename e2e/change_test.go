package e2e_test

import (
	"context"
	"encoding/json"
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
	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient"
	"github.com/mrgyatso/keyhole/internal/agent"
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

// Change contents used through the run.
const (
	cfg0 = "mode=prod\nlevel=info\nretries=3\n"  // on disk at enrolment
	cfg1 = "mode=prod\nlevel=debug\nretries=3\n" // the first approved change
	cfg2 = "mode=prod\nlevel=trace\nretries=3\n" // a second prepared change
	cfg3 = "mode=prod\nlevel=warn\nretries=9\n"  // a third party edits the file
)

// changeEnv is one running relay + agent over real NATS, reachable both
// through the MCP gateway and, for the idempotency check, directly on the
// client's NATS account.
type changeEnv struct {
	ctx      context.Context
	ac       *adminclient.Client
	priv     string // private listener URL, for MCP
	conns    *relay.ConnManager
	aud      *audit.JetStreamStore
	slug     string
	deviceID string
	root     string
	file     string
}

// setupChange enrols one device with a change store and an allow rule over a
// scratch directory, and opens an MCP session-minting admin client.
func setupChange(t *testing.T) (*changeEnv, *mcp.ClientSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	op, err := natsauth.NewOperator("e2e-change")
	check(t, err)
	ns := natsauthtest.StartServer(t, op)
	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	check(t, err)
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.DiscardHandler)
	conns := relay.NewConnManager(ns.ClientURL(), st, log)
	t.Cleanup(conns.Close)
	aud := audit.NewJetStreamStore(conns)
	gw, err := gateway.New(gateway.Config{Directory: st, Access: st, Conns: conns, Audit: aud})
	check(t, err)
	sys, err := op.NewSysUser("relay")
	check(t, err)
	srv, err := relay.New(relay.Config{Store: st, Conns: conns, Operator: op, SysCreds: sys, Audit: aud,
		AgentNATSURLs: []string{ns.ClientURL()}, MCP: gw.Handler(), Logger: log})
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
	red, err := redact.New()
	check(t, err)

	const slug = "acme"
	_, err = ac.CreateClient(ctx, adminapi.CreateClientRequest{Slug: slug, Name: "ACME"})
	check(t, err)
	root, err := filepath.EvalSymlinks(t.TempDir())
	check(t, err)
	file := filepath.Join(root, "app.conf")
	check(t, os.WriteFile(file, []byte(cfg0), 0o600))
	p, err := ac.GetPolicy(ctx, slug)
	check(t, err)
	p.Allow[runtime.GOOS] = []proto.AllowRule{{ID: "scratch", Path: root}}
	_, err = ac.PutPolicy(ctx, slug, p)
	check(t, err)
	tok, err := ac.MintToken(ctx, slug, adminapi.MintTokenRequest{})
	check(t, err)

	data := agent.DataDir(filepath.Join(t.TempDir(), "agent"))
	host := hostinfo.Info{Hostname: "acme-box", MachineID: "acme-machine", OS: runtime.GOOS, Arch: runtime.GOARCH}
	enrollment, err := agent.Enroll(ctx, agent.EnrollOptions{RelayURL: pub.URL, Token: tok.Secret, Org: slug, DataDir: data, Host: host})
	check(t, err)
	// A real change store, so the endpoint actually stages and writes. The plan
	// approver is nil: the gates are the capability and the recorded digest.
	x := fstools.New(fstools.Options{Redactor: red, ChangeDir: data.File(agent.ChangeSubdir)})
	runner, err := agent.NewRunner(agent.RunnerOptions{Enrollment: enrollment, CredsFile: data.CredsPath(),
		Executor: x, Host: host, Logger: log, Consent: consentAdapter{}})
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

	sess, err := ac.MintSession(ctx, slug, adminapi.MintSessionRequest{Tech: "e2e-tech"})
	check(t, err)
	mc := mcp.NewClient(&mcp.Implementation{Name: "change", Version: "test"}, nil)
	cs, err := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: priv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer(sess.Bearer)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	check(t, err)
	t.Cleanup(func() { cs.Close() })
	return &changeEnv{ctx: ctx, ac: ac, priv: priv.URL, conns: conns, aud: aud,
		slug: slug, deviceID: enrollment.DeviceID, root: root, file: file}, cs
}

// planFields pulls the plan ID and digest out of prepare's rendered summary,
// whose first line is "… | plan: <id> | digest: <digest>".
func planFields(t *testing.T, text string) (id, digest string) {
	t.Helper()
	for _, f := range strings.Split(strings.SplitN(text, "\n", 2)[0], " | ") {
		if k, v, ok := strings.Cut(f, ": "); ok {
			switch strings.TrimSpace(k) {
			case "plan":
				id = strings.TrimSpace(v)
			case "digest":
				digest = strings.TrimSpace(v)
			}
		}
	}
	if id == "" || digest == "" {
		t.Fatalf("no plan in prepare output:\n%s", text)
	}
	return id, digest
}

func TestStructuredRemediationE2E(t *testing.T) {
	env, cs := setupChange(t)
	ctx := env.ctx
	call := func(tool string, args map[string]any) (string, bool) {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		check(t, err)
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text)
			}
		}
		return b.String(), res.IsError
	}

	// request_access for the change operations → approved by the test adapter.
	text, bad := call("request_access", map[string]any{"device": env.deviceID, "purpose": "fix the vendor config",
		"paths": []string{env.root}, "duration_minutes": 10,
		"operations": []string{proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange}})
	if bad {
		t.Fatalf("request_access: %s", text)
	}
	var grant model.AccessRequest
	check(t, json.Unmarshal([]byte(text), &grant))
	deadline := time.Now().Add(10 * time.Second)
	for grant.State != model.AccessApproved && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		text, bad = call("access_status", map[string]any{"access_id": grant.ID})
		if bad {
			t.Fatalf("access_status: %s", text)
		}
		check(t, json.Unmarshal([]byte(text), &grant))
	}
	if grant.State != model.AccessApproved {
		t.Fatalf("grant state %q", grant.State)
	}
	for _, want := range []string{proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange} {
		if !contains(grant.EffectiveOperations, want) {
			t.Fatalf("grant is missing %s: %v", want, grant.EffectiveOperations)
		}
	}

	// prepare stages the change without touching the target.
	text, bad = call(proto.OpPrepareFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID,
		"path": env.file, "content": cfg1, "reason": "lower the log level"})
	if bad {
		t.Fatalf("prepare: %s", text)
	}
	if !strings.Contains(text, "Nothing has been written yet") {
		t.Errorf("prepare did not say the file is untouched:\n%s", text)
	}
	planID, digest := planFields(t, text)
	if got := onDisk(t, env.file); got != cfg0 {
		t.Fatalf("prepare changed the file: %q", got)
	}

	// A digest the grant did not issue never reaches the machine.
	text, bad = call(proto.OpApplyFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID,
		"plan_id": planID, "plan_digest": strings.Repeat("0", 64)})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("apply with a foreign digest: %s", text)
	}
	if got := onDisk(t, env.file); got != cfg0 {
		t.Fatalf("a mismatched apply still wrote: %q", got)
	}

	// The real apply writes the staged content and leaves a rollback copy.
	text, bad = call(proto.OpApplyFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID,
		"plan_id": planID, "plan_digest": digest})
	if bad || !strings.Contains(text, `"rollback_id"`) {
		t.Fatalf("apply: %s", text)
	}
	if got := onDisk(t, env.file); got != cfg1 {
		t.Fatalf("apply did not write the staged content: %q", got)
	}

	// rollback restores the pre-change content.
	text, bad = call(proto.OpRollbackFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID, "plan_id": planID})
	if bad {
		t.Fatalf("rollback: %s", text)
	}
	if got := onDisk(t, env.file); got != cfg0 {
		t.Fatalf("rollback did not restore the file: %q", got)
	}

	// A stale plan: prepare, then a third party edits the file, so the apply is
	// refused and the file keeps the third party's content.
	text, bad = call(proto.OpPrepareFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID,
		"path": env.file, "content": cfg2, "reason": "raise the log level"})
	if bad {
		t.Fatalf("second prepare: %s", text)
	}
	stalePlan, staleDigest := planFields(t, text)
	check(t, os.WriteFile(env.file, []byte(cfg3), 0o600)) // edited after review
	text, bad = call(proto.OpApplyFileChange, map[string]any{"device": env.deviceID, "access_id": grant.ID,
		"plan_id": stalePlan, "plan_digest": staleDigest})
	if !bad || !strings.Contains(text, proto.ErrStalePlan) {
		t.Fatalf("stale apply: %s", text)
	}
	if got := onDisk(t, env.file); got != cfg3 {
		t.Fatalf("a stale apply overwrote the third party's change: %q", got)
	}

	// Every step and every refusal is audited, and the chain verifies from a
	// freshly opened store.
	reopened := audit.NewJetStreamStore(env.conns)
	v, err := reopened.Verify(ctx, env.slug)
	check(t, err)
	if !v.OK || v.Entries == 0 {
		t.Fatalf("audit chain: %+v", v)
	}
	var entries []audit.Entry
	check(t, reopened.Range(ctx, env.slug, time.Time{}, time.Time{}, func(e audit.Entry) error {
		entries = append(entries, e)
		return nil
	}))
	transitions := map[string]bool{}
	var sawApply, sawDigestDenial, sawStale bool
	for _, e := range entries {
		if e.Kind == audit.KindConsent {
			transitions[e.Tool] = true
		}
		if e.Tool == proto.OpApplyFileChange && e.Result == audit.ResultOK {
			var cm proto.ChangeMeta
			if json.Unmarshal(e.Change, &cm) == nil && cm.PlanID != "" && cm.BeforeSHA256 != "" && cm.AfterSHA256 != "" {
				sawApply = true
			}
		}
		if e.Tool == proto.OpApplyFileChange && e.Result == audit.ResultDenied && e.ErrorCode == proto.ErrGrantInvalid {
			sawDigestDenial = true
		}
		if e.Tool == proto.OpApplyFileChange && e.ErrorCode == proto.ErrStalePlan {
			sawStale = true
		}
	}
	if !sawApply {
		t.Error("audit has no successful apply carrying plan and hash metadata")
	}
	if !sawDigestDenial {
		t.Error("audit did not record the refused digest mismatch")
	}
	if !sawStale {
		t.Error("audit did not record the refused stale apply")
	}
	for _, state := range []string{model.AccessRequested, model.AccessAwaiting, model.AccessApproved, model.AccessActive} {
		if !transitions["access."+state] {
			t.Errorf("audit missing consent transition %s", state)
		}
	}

	// Idempotency by request ID lives at the endpoint, and the gateway mints a
	// fresh request ID per call, so the replay is driven directly on the
	// client's NATS account.
	env.idempotentApplyOverNATS(t)
}

// idempotentApplyOverNATS obtains a capability straight from the endpoint and
// sends the same apply request ID twice: the second is a replay that returns
// the same result and writes nothing.
func (env *changeEnv) idempotentApplyOverNATS(t *testing.T) {
	t.Helper()
	nc, err := env.conns.Conn(env.slug)
	check(t, err)
	sub, err := nc.SubscribeSync(proto.EventSubject(env.deviceID, proto.EvtConsent))
	check(t, err)
	defer sub.Unsubscribe()
	bfile := filepath.Join(env.root, "idem.conf")
	check(t, os.WriteFile(bfile, []byte(cfg0), 0o600))

	now := time.Now().UTC()
	cr := proto.ConsentRequest{AccessID: "acc_idem", Client: env.slug, Device: env.deviceID, Technician: "e2e-direct",
		Purpose: "idempotency", Operations: []string{proto.OpPrepareFileChange, proto.OpApplyFileChange},
		Paths: []string{env.root}, Duration: 10 * time.Minute, ExpiresAt: now.Add(10 * time.Minute), PolicyVersion: 1}
	var dec proto.ConsentDecision
	env.rpc(t, nc, proto.OpRequestAccess, "req_idem_grant", cr, nil, &dec)
	if dec.State != proto.ConsentAwaiting {
		t.Fatalf("endpoint did not acknowledge consent: %+v", dec)
	}
	m, err := sub.NextMsg(10 * time.Second)
	check(t, err)
	var event proto.ConsentEvent
	check(t, json.Unmarshal(m.Data, &event))
	if event.Capability == nil {
		t.Fatalf("endpoint did not issue a capability: %+v", event)
	}
	cap := event.Capability

	var plan proto.PrepareFileChangeResult
	env.rpc(t, nc, proto.OpPrepareFileChange, "req_idem_prep",
		proto.PrepareFileChangeArgs{Path: bfile, Content: cfg1}, cap, &plan)

	var first proto.ApplyFileChangeResult
	env.rpc(t, nc, proto.OpApplyFileChange, "req_idem_apply",
		proto.ApplyFileChangeArgs{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest}, cap, &first)
	if first.Replayed || onDisk(t, bfile) != cfg1 {
		t.Fatalf("first apply: replayed=%v content=%q", first.Replayed, onDisk(t, bfile))
	}
	info, err := os.Stat(bfile)
	check(t, err)

	var second proto.ApplyFileChangeResult
	env.rpc(t, nc, proto.OpApplyFileChange, "req_idem_apply", // same request ID
		proto.ApplyFileChangeArgs{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest}, cap, &second)
	if !second.Replayed || second.RollbackID != first.RollbackID || second.AfterSHA256 != first.AfterSHA256 {
		t.Fatalf("replay returned a different result: %+v vs %+v", second, first)
	}
	if again, err := os.Stat(bfile); err != nil || !again.ModTime().Equal(info.ModTime()) {
		t.Error("the replayed apply wrote the file a second time")
	}
}

// rpc sends one request to the device over nc with the given op, request ID
// and capability, and decodes a successful result into out.
func (env *changeEnv) rpc(t *testing.T, nc *nats.Conn, op, id string, args any, cap *proto.Capability, out any) {
	t.Helper()
	raw, err := json.Marshal(args)
	check(t, err)
	req := proto.Request{V: proto.Version, ID: id, Op: op, Args: raw,
		Policy:   proto.Policy{Version: 1},
		Caller:   proto.Caller{Tech: "e2e-direct"},
		Deadline: time.Now().Add(20 * time.Second), Capability: cap}
	if cap != nil {
		req.Caller.Tech = cap.Technician
	}
	data, err := json.Marshal(req)
	check(t, err)
	msg, err := nc.Request(proto.RPCSubject(env.deviceID, op), data, 15*time.Second)
	check(t, err)
	var resp proto.Response
	check(t, json.Unmarshal(msg.Data, &resp))
	if !resp.OK {
		t.Fatalf("%s over NATS: %+v", op, resp.Error)
	}
	check(t, json.Unmarshal(resp.Result, out))
}

func onDisk(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	check(t, err)
	return string(b)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
