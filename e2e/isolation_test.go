package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type bearer string

// consentAdapter is an endpoint user who answers at once, which keeps this
// tenant-isolation gate about isolation. The asynchronous consent path,
// where a person takes minutes, is exercised in consent_test.go.
type consentAdapter struct{}

func (consentAdapter) Request(_ context.Context, r proto.ConsentRequest) (<-chan proto.ConsentUpdate, error) {
	u := proto.ConsentUpdate{State: model.AccessApproved, Approver: "local-user", Final: true,
		Paths: append([]string(nil), r.Paths...), Operations: append([]string(nil), r.Operations...)}
	switch {
	case strings.Contains(r.Purpose, "deny"):
		u = proto.ConsentUpdate{State: model.AccessDenied, Approver: "local-user", Reason: "declined", Final: true}
	case strings.Contains(r.Purpose, "narrow"):
		u.State, u.Paths = model.AccessNarrowed, u.Paths[:1]
	}
	ch := make(chan proto.ConsentUpdate, 1)
	ch <- u
	close(ch)
	return ch, nil
}

func (consentAdapter) Activity(proto.ConsentActivity) {}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

// This gate uses real enrollment, device credentials, agent execution, MCP,
// SQLite, and per-account JetStream. No directory or audit doubles are used.
func TestCrossTenantGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	op, err := natsauth.NewOperator("e2e")
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
	srv, err := relay.New(relay.Config{Store: st, Conns: conns, Operator: op, SysCreds: sys, Audit: aud, AgentNATSURLs: []string{ns.ClientURL()}, MCP: gw.Handler(), Logger: log, Reports: map[string]relay.ReportWriter{
		"csv": func(w io.Writer, _ relay.ReportMeta, entries []audit.Entry, _ audit.VerifyResult) error {
			return audit.WriteCSV(w, entries)
		},
		"pdf": func(w io.Writer, m relay.ReportMeta, entries []audit.Entry, v audit.VerifyResult) error {
			return audit.WritePDF(w, audit.ReportMeta{Client: m.Client, ClientName: m.ClientName, From: m.From, To: m.To, GeneratedAt: m.GeneratedAt}, entries, v)
		},
	}})
	check(t, err)
	check(t, srv.Start(ctx))
	t.Cleanup(srv.Close)
	adminToken := model.NewSecret(model.SecretAdmin)
	check(t, st.SetAdminTokenHash(ctx, model.HashSecret(adminToken), time.Now()))
	pub := httptest.NewServer(srv.PublicHandler())
	t.Cleanup(pub.Close)
	priv := httptest.NewServer(srv.PrivateHandler())
	t.Cleanup(priv.Close)
	ac := adminclient.New(priv.URL, adminToken, "gate-tech", nil)
	red, err := redact.New()
	check(t, err)
	type endpoint struct {
		id, root string
		session  *mcp.ClientSession
	}
	endpoints := map[string]endpoint{}
	for _, slug := range []string{"acme", "globex"} {
		_, err = ac.CreateClient(ctx, adminapi.CreateClientRequest{Slug: slug, Name: slug})
		check(t, err)
		root, err := filepath.EvalSymlinks(t.TempDir())
		check(t, err)
		check(t, os.WriteFile(filepath.Join(root, "app.log"), []byte(slug+" operational log\npassword=SuperSecretValue123!\n"), 0600))
		check(t, os.WriteFile(filepath.Join(root, "vault.kdbx"), []byte("never expose password database"), 0600))
		p, err := ac.GetPolicy(ctx, slug)
		check(t, err)
		p.Allow[runtime.GOOS] = []proto.AllowRule{{ID: "test-logs", Path: root}}
		_, err = ac.PutPolicy(ctx, slug, p)
		check(t, err)
		tok, err := ac.MintToken(ctx, slug, adminapi.MintTokenRequest{})
		check(t, err)
		data := agent.DataDir(filepath.Join(t.TempDir(), "agent"))
		host := hostinfo.Info{Hostname: slug + "-server", MachineID: slug + "-machine", OS: runtime.GOOS, Arch: runtime.GOARCH}
		enrollment, err := agent.Enroll(ctx, agent.EnrollOptions{RelayURL: pub.URL, Token: tok.Secret, Org: slug, DataDir: data, Host: host})
		check(t, err)
		runner, err := agent.NewRunner(agent.RunnerOptions{Enrollment: enrollment, CredsFile: data.CredsPath(), Executor: fstools.New(fstools.Options{Redactor: red}), Host: host, Logger: log, Consent: consentAdapter{}})
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
		sess, err := ac.MintSession(ctx, slug, adminapi.MintSessionRequest{Tech: "gate-tech"})
		check(t, err)
		mc := mcp.NewClient(&mcp.Implementation{Name: "gate", Version: "test"}, nil)
		cs, err := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: priv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer(sess.Bearer)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
		check(t, err)
		t.Cleanup(func() { cs.Close() })
		endpoints[slug] = endpoint{enrollment.DeviceID, root, cs}
	}
	call := func(cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
		t.Helper()
		result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		check(t, err)
		var out strings.Builder
		for _, c := range result.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				out.WriteString(text.Text)
			}
		}
		return out.String(), result.IsError
	}
	// A second enrolled ACME device proves grants cannot move between devices
	// even while the client and technician remain the same.
	tok2, err := ac.MintToken(ctx, "acme", adminapi.MintTokenRequest{})
	check(t, err)
	data2 := agent.DataDir(filepath.Join(t.TempDir(), "agent"))
	host2 := hostinfo.Info{Hostname: "acme-other", MachineID: "acme-other-machine", OS: runtime.GOOS, Arch: runtime.GOARCH}
	enroll2, err := agent.Enroll(ctx, agent.EnrollOptions{RelayURL: pub.URL, Token: tok2.Secret, Org: "acme", DataDir: data2, Host: host2})
	check(t, err)
	runner2, err := agent.NewRunner(agent.RunnerOptions{Enrollment: enroll2, CredsFile: data2.CredsPath(), Executor: fstools.New(fstools.Options{Redactor: red}), Host: host2, Logger: log, Consent: consentAdapter{}})
	check(t, err)
	run2, stop2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- runner2.Run(run2) }()
	t.Cleanup(func() {
		stop2()
		select {
		case <-done2:
		case <-time.After(5 * time.Second):
			t.Error("second agent shutdown timed out")
		}
	})
	for {
		d, e := st.Device(ctx, enroll2.DeviceID)
		if e == nil && d.Online(time.Now()) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("second device did not become online")
		case <-time.After(10 * time.Millisecond):
		}
	}
	a, b := endpoints["acme"], endpoints["globex"]
	text, bad := call(a.session, "list_devices", map[string]any{})
	if bad || !strings.Contains(text, a.id) || strings.Contains(text, b.id) {
		t.Fatalf("tenant device list isolation failed: %s", text)
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log")})
	if bad || !strings.Contains(text, "acme operational log") || strings.Contains(text, "SuperSecretValue123!") || !strings.Contains(text, "REDACTED") {
		t.Fatalf("read/redaction failed: %s", text)
	}
	for _, device := range []string{b.id, "globex-server"} {
		text, bad = call(a.session, "read_file", map[string]any{"device": device, "path": filepath.Join(b.root, "app.log")})
		if !bad || !strings.Contains(text, proto.ErrUnknownDevice) || strings.Contains(text, "globex operational log") {
			t.Fatalf("cross tenant read: %s", text)
		}
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "vault.kdbx")})
	if !bad || !strings.Contains(text, proto.ErrHardDenied) {
		t.Fatalf("hard deny failed: %s", text)
	}
	// decided polls the durable consent record, which is where an endpoint
	// decision lands: request_access only acknowledges.
	decided := func(cs *mcp.ClientSession, id string) model.AccessRequest {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			text, bad := call(cs, "access_status", map[string]any{"access_id": id})
			if bad {
				t.Fatalf("access_status: %s", text)
			}
			var got model.AccessRequest
			check(t, json.Unmarshal([]byte(text), &got))
			if got.State != model.AccessAwaiting && got.State != model.AccessRequested {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("access %s never left %s", id, got.State)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Consented read: approve a narrowed scope, use it, reject wrong bindings,
	// terminate it, and reject replay. The legacy read above proves migration compatibility.
	text, bad = call(a.session, "request_access", map[string]any{"device": a.id, "purpose": "narrow diagnostics", "paths": []string{a.root, filepath.Dir(a.root)}, "duration_minutes": 10})
	if bad {
		t.Fatalf("request access: %s", text)
	}
	var granted model.AccessRequest
	check(t, json.Unmarshal([]byte(text), &granted))
	if granted.State != model.AccessAwaiting {
		t.Fatalf("request_access did not acknowledge asynchronously: %+v", granted)
	}
	granted = decided(a.session, granted.ID)
	if granted.State != model.AccessApproved || len(granted.EffectiveScope) != 1 {
		t.Fatalf("narrowed grant: %+v", granted)
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log"), "access_id": granted.ID})
	if bad || !strings.Contains(text, "acme operational log") {
		t.Fatalf("granted read: %s", text)
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": enroll2.DeviceID, "path": filepath.Join(a.root, "app.log"), "access_id": granted.ID})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("wrong device grant: %s", text)
	}
	text, bad = call(b.session, "read_file", map[string]any{"device": b.id, "path": filepath.Join(b.root, "app.log"), "access_id": granted.ID})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("wrong client grant: %s", text)
	}
	other, err := ac.MintSession(ctx, "acme", adminapi.MintSessionRequest{Tech: "other-tech"})
	check(t, err)
	mc2 := mcp.NewClient(&mcp.Implementation{Name: "other", Version: "test"}, nil)
	otherCS, err := mc2.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: priv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer(other.Bearer)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	check(t, err)
	defer otherCS.Close()
	text, bad = call(otherCS, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log"), "access_id": granted.ID})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("wrong technician grant: %s", text)
	}
	text, bad = call(a.session, "end_access", map[string]any{"access_id": granted.ID})
	if bad {
		t.Fatalf("end access: %s", text)
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log"), "access_id": granted.ID})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("terminated replay: %s", text)
	}
	text, bad = call(a.session, "request_access", map[string]any{"device": a.id, "purpose": "deny diagnostics", "paths": []string{a.root}, "duration_minutes": 10})
	if bad {
		t.Fatalf("denial response: %s", text)
	}
	var deniedAccess model.AccessRequest
	check(t, json.Unmarshal([]byte(text), &deniedAccess))
	if deniedAccess = decided(a.session, deniedAccess.ID); deniedAccess.State != model.AccessDenied {
		t.Fatalf("denial state: %+v", deniedAccess)
	}
	text, bad = call(a.session, "request_access", map[string]any{"device": a.id, "purpose": "expire diagnostics", "paths": []string{a.root}, "duration_minutes": 10})
	if bad {
		t.Fatalf("expiry request: %s", text)
	}
	var exp model.AccessRequest
	check(t, json.Unmarshal([]byte(text), &exp))
	exp = decided(a.session, exp.ID)
	exp.ExpiresAt = time.Now().Add(-time.Second)
	check(t, st.UpdateAccess(ctx, exp))
	text, bad = call(a.session, "access_status", map[string]any{"access_id": exp.ID})
	if bad || !strings.Contains(text, model.AccessExpired) {
		t.Fatalf("expired status: %s", text)
	}
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log"), "access_id": exp.ID})
	if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("expired grant: %s", text)
	}
	for _, path := range []string{"/mcp", "/v1/admin/clients"} {
		resp, err := http.Get(pub.URL + path)
		check(t, err)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("public %s status %d", path, resp.StatusCode)
		}
	}
	for _, slug := range []string{"acme", "globex"} {
		v, err := ac.AuditVerify(ctx, slug)
		check(t, err)
		if !v.OK || v.Entries == 0 {
			t.Fatalf("audit chain %s: %+v", slug, v)
		}
	}

	// Reopen the audit store to prove verification uses durable state.
	reopened := audit.NewJetStreamStore(conns)
	verified, err := reopened.Verify(ctx, "acme")
	check(t, err)
	if !verified.OK || verified.Entries == 0 {
		t.Fatalf("reopened audit: %+v", verified)
	}
	var entries []audit.Entry
	check(t, reopened.Range(ctx, "acme", time.Time{}, time.Time{}, func(e audit.Entry) error { entries = append(entries, e); return nil }))
	var sawRead, sawDenial, sawGrantDenial bool
	transitions := map[string]bool{}
	for _, e := range entries {
		if e.Kind == audit.KindConsent {
			transitions[e.Tool] = true
		}
		if e.Tool == "read_file" && e.Result == audit.ResultOK && e.Redactions > 0 && e.SHA256 != "" {
			sawRead = true
		}
		if e.ErrorCode == proto.ErrUnknownDevice {
			sawDenial = true
		}
		if e.ErrorCode == proto.ErrGrantInvalid {
			sawGrantDenial = true
		}
	}
	if !sawRead || !sawDenial || !sawGrantDenial {
		t.Fatal("audit missing redacted read, cross-tenant denial, or refused grant operation")
	}
	for _, state := range []string{model.AccessRequested, model.AccessAwaiting, model.AccessNarrowed, model.AccessApproved, model.AccessActive, model.AccessDenied, model.AccessExpired, model.AccessTerminated} {
		if !transitions["access."+state] {
			t.Fatalf("audit missing consent transition %s", state)
		}
	}
	for _, format := range []string{"csv", "pdf"} {
		var out bytes.Buffer
		_, err := ac.AuditExport(ctx, "acme", adminclient.AuditQuery{Format: format}, &out)
		check(t, err)
		if out.Len() == 0 || bytes.Contains(out.Bytes(), []byte("SuperSecretValue123!")) {
			t.Fatalf("invalid %s report", format)
		}
		if format == "pdf" && !bytes.HasPrefix(out.Bytes(), []byte("%PDF-")) {
			t.Fatal("report is not a PDF")
		}
	}
	_, err = ac.DisableClient(ctx, "acme", "e2e kill switch")
	check(t, err)
	text, bad = call(a.session, "read_file", map[string]any{"device": a.id, "path": filepath.Join(a.root, "app.log")})
	if !bad || !strings.Contains(text, proto.ErrClientDisabled) {
		t.Fatalf("kill switch failed: %s", text)
	}
}
