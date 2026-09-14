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

// consentWindow is the endpoint's own deadline in these tests. Five minutes
// is right for a person and wrong for a test, so the endpoint's window is
// shortened while everything else stays real.
const consentWindow = 400 * time.Millisecond

// stack is one whole Keyhole: NATS with real per-client accounts, the store,
// the relay, the MCP gateway, one enrolled endpoint running the real agent,
// and a scriptable consent application standing in for the Windows UI.
type stack struct {
	t        *testing.T
	ctx      context.Context
	store    *store.Store
	audit    audit.Store
	admin    *adminclient.Client
	session  *mcp.ClientSession
	script   *consentscript.Adapter
	deviceID string
	root     string // the directory the client's policy allows
	logPath  string
	restart  func() // stop the agent and start a new one with the same data dir
}

func newStack(t *testing.T, ctx context.Context) *stack {
	t.Helper()
	script := consentscript.New()
	s := newStackWith(t, ctx, func() agent.ConsentAdapter { return script })
	s.script = script
	return s
}

// newStackWith builds the stack around the consent adapter that consent
// returns. The endpoint calls it again on every restart, as a restarted
// service builds its consent transport again.
func newStackWith(t *testing.T, ctx context.Context, consent func() agent.ConsentAdapter) *stack {
	t.Helper()
	op, err := natsauth.NewOperator("consent")
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
	ac := adminclient.New(priv.URL, adminToken, "consent-tech", nil)
	_, err = ac.CreateClient(ctx, adminapi.CreateClientRequest{Slug: "acme", Name: "ACME"})
	check(t, err)

	root, err := filepath.EvalSymlinks(t.TempDir())
	check(t, err)
	check(t, os.WriteFile(filepath.Join(root, "app.log"), []byte("acme operational log\n"), 0600))
	p, err := ac.GetPolicy(ctx, "acme")
	check(t, err)
	p.Allow[runtime.GOOS] = []proto.AllowRule{{ID: "test-logs", Path: root}}
	_, err = ac.PutPolicy(ctx, "acme", p)
	check(t, err)
	tok, err := ac.MintToken(ctx, "acme", adminapi.MintTokenRequest{})
	check(t, err)

	data := agent.DataDir(filepath.Join(t.TempDir(), "agent"))
	host := hostinfo.Info{Hostname: "acme-desk", MachineID: "acme-machine", OS: runtime.GOOS, Arch: runtime.GOARCH}
	enrollment, err := agent.Enroll(ctx, agent.EnrollOptions{RelayURL: pub.URL, Token: tok.Secret, Org: "acme", DataDir: data, Host: host})
	check(t, err)
	red, err := redact.New()
	check(t, err)

	s := &stack{t: t, ctx: ctx, store: st, audit: aud, admin: ac,
		deviceID: enrollment.DeviceID, root: root, logPath: filepath.Join(root, "app.log")}
	grants := data.File("grants.json")
	start := func() func() {
		runner, err := agent.NewRunner(agent.RunnerOptions{Enrollment: enrollment, CredsFile: data.CredsPath(),
			Executor: fstools.New(fstools.Options{Redactor: red}), Host: host, Logger: log,
			Consent: consent(), GrantsFile: grants, ConsentWindow: consentWindow})
		check(t, err)
		runCtx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runner.Run(runCtx) }()
		return func() {
			stop()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("agent shutdown timed out")
			}
		}
	}
	stop := start()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			stop()
		}
	})
	s.restart = func() {
		stop()
		stopped = true
		stop = start()
		stopped = false
		s.waitOnline()
	}
	s.waitOnline()

	sess, err := ac.MintSession(ctx, "acme", adminapi.MintSessionRequest{Tech: "consent-tech"})
	check(t, err)
	mc := mcp.NewClient(&mcp.Implementation{Name: "consent", Version: "test"}, nil)
	cs, err := mc.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: priv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer(sess.Bearer)}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	check(t, err)
	t.Cleanup(func() { cs.Close() })
	s.session = cs
	return s
}

func (s *stack) waitOnline() {
	s.t.Helper()
	for {
		d, err := s.store.Device(s.ctx, s.deviceID)
		if err == nil && d.Online(time.Now()) {
			return
		}
		select {
		case <-s.ctx.Done():
			s.t.Fatal("device did not become online")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (s *stack) call(tool string, args map[string]any) (string, bool) {
	s.t.Helper()
	result, err := s.session.CallTool(s.ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	check(s.t, err)
	var out strings.Builder
	for _, c := range result.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			out.WriteString(text.Text)
		}
	}
	return out.String(), result.IsError
}

// request asks for access and returns the acknowledged record. The endpoint
// only acks: request_access must never block on a person.
func (s *stack) request(purpose string, paths ...string) model.AccessRequest {
	s.t.Helper()
	if len(paths) == 0 {
		paths = []string{s.root}
	}
	began := time.Now()
	text, bad := s.call(proto.OpRequestAccess, map[string]any{"device": s.deviceID, "purpose": purpose,
		"paths": paths, "duration_minutes": 10})
	if bad {
		s.t.Fatalf("request_access: %s", text)
	}
	if waited := time.Since(began); waited > 5*time.Second {
		s.t.Fatalf("request_access blocked for %s; consent must be asynchronous", waited)
	}
	var a model.AccessRequest
	check(s.t, json.Unmarshal([]byte(text), &a))
	if a.State != model.AccessAwaiting {
		s.t.Fatalf("request_access returned state %q, want %q", a.State, model.AccessAwaiting)
	}
	return a
}

// conversation returns the request as the consent application sees it.
func (s *stack) conversation(accessID string) *consentscript.Conversation {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	c, err := s.script.Wait(ctx, accessID)
	check(s.t, err)
	return c
}

// status polls access_status until the durable state is one of want.
func (s *stack) status(accessID string, want ...string) model.AccessRequest {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var a model.AccessRequest
	for {
		text, bad := s.call("access_status", map[string]any{"access_id": accessID})
		if bad {
			s.t.Fatalf("access_status: %s", text)
		}
		check(s.t, json.Unmarshal([]byte(text), &a))
		for _, w := range want {
			if a.State == w {
				return a
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("access %s is %q (reason %q), want one of %v", accessID, a.State, a.Reason, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *stack) read(accessID string) (string, bool) {
	s.t.Helper()
	args := map[string]any{"device": s.deviceID, "path": s.logPath}
	if accessID != "" {
		args["access_id"] = accessID
	}
	return s.call(proto.OpReadFile, args)
}

// TestAsyncConsentLifecycle covers the endpoint-driven states a person
// produces minutes after the request: approval and use, narrowing, denial,
// the endpoint's own consent deadline, nobody being signed in, pausing and
// resuming, the user ending a session, and the first session to answer
// winning. Every one of them is durable and audited without request_access
// having waited for it.
func TestAsyncConsentLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s := newStack(t, ctx)

	t.Run("approve then use", func(t *testing.T) {
		a := s.request("approve diagnostics")
		if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("undecided grant allowed a read: %s", text)
		}
		s.conversation(a.ID).ApproveFrom("local-user", "2")
		got := s.status(a.ID, model.AccessApproved)
		if got.Approver != "local-user" || got.ApproverSession != "2" {
			t.Fatalf("approver not recorded: %+v", got)
		}
		text, bad := s.read(a.ID)
		if bad || !strings.Contains(text, "acme operational log") {
			t.Fatalf("approved read: %s", text)
		}
		s.status(a.ID, model.AccessActive)
		// The endpoint user sees what the session did.
		var seen bool
		for _, act := range s.script.Activities() {
			seen = seen || (act.AccessID == a.ID && act.Op == proto.OpReadFile && act.Path == s.logPath && act.Bytes > 0)
		}
		if !seen {
			t.Fatalf("the consent application was not shown the read: %+v", s.script.Activities())
		}
	})

	t.Run("narrow", func(t *testing.T) {
		a := s.request("narrow diagnostics", s.root, filepath.Dir(s.root))
		s.conversation(a.ID).Narrow("local-user", s.root)
		got := s.status(a.ID, model.AccessApproved)
		if len(got.EffectiveScope) != 1 || got.EffectiveScope[0] != s.root {
			t.Fatalf("narrowed scope: %+v", got.EffectiveScope)
		}
		if text, bad := s.read(got.ID); bad || !strings.Contains(text, "acme operational log") {
			t.Fatalf("narrowed read: %s", text)
		}
	})

	t.Run("deny", func(t *testing.T) {
		a := s.request("deny diagnostics")
		s.conversation(a.ID).Deny("local-user", "not now")
		got := s.status(a.ID, model.AccessDenied)
		if got.Reason != "not now" {
			t.Fatalf("denial reason: %+v", got)
		}
		if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("denied grant allowed a read: %s", text)
		}
	})

	t.Run("endpoint consent timeout", func(t *testing.T) {
		a := s.request("ignored diagnostics")
		s.conversation(a.ID) // shown, never answered
		got := s.status(a.ID, model.AccessDenied)
		if got.Reason != proto.ReasonTimeout {
			t.Fatalf("timeout reason: %+v", got)
		}
	})

	t.Run("no interactive user", func(t *testing.T) {
		a := s.request("unattended diagnostics")
		s.conversation(a.ID).Waiting(proto.ReasonNoUser)
		got := s.status(a.ID, model.AccessDenied)
		if got.Reason != proto.ReasonNoUser {
			t.Fatalf("no-user reason: %+v", got)
		}
	})

	t.Run("pause blocks reads then resume", func(t *testing.T) {
		a := s.request("pause diagnostics")
		conv := s.conversation(a.ID)
		conv.Approve("local-user")
		s.status(a.ID, model.AccessApproved)
		conv.Pause()
		s.status(a.ID, model.AccessPaused)
		text, bad := s.read(a.ID)
		if !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("paused grant allowed a read: %s", text)
		}
		conv.Resume()
		s.status(a.ID, model.AccessApproved)
		if text, bad := s.read(a.ID); bad || !strings.Contains(text, "acme operational log") {
			t.Fatalf("resumed read: %s", text)
		}
	})

	t.Run("user terminates", func(t *testing.T) {
		a := s.request("terminate diagnostics")
		conv := s.conversation(a.ID)
		conv.Approve("local-user")
		s.status(a.ID, model.AccessApproved)
		conv.Terminate(proto.ReasonUser)
		got := s.status(a.ID, model.AccessTerminated)
		if got.Reason != proto.ReasonUser {
			t.Fatalf("termination reason: %+v", got)
		}
		if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("terminated grant allowed a read: %s", text)
		}
	})

	t.Run("user signs out", func(t *testing.T) {
		a := s.request("logoff diagnostics")
		conv := s.conversation(a.ID)
		conv.Approve("local-user")
		s.status(a.ID, model.AccessApproved)
		conv.Terminate(proto.ReasonLogoff)
		if got := s.status(a.ID, model.AccessTerminated); got.Reason != proto.ReasonLogoff {
			t.Fatalf("logoff reason: %+v", got)
		}
	})

	t.Run("first session to answer wins", func(t *testing.T) {
		a := s.request("multi-session diagnostics")
		conv := s.conversation(a.ID)
		conv.ApproveFrom("first-user", "2")
		conv.Deny("second-user", "too late")
		got := s.status(a.ID, model.AccessApproved)
		if got.Approver != "first-user" || got.ApproverSession != "2" {
			t.Fatalf("a later session overrode the first decision: %+v", got)
		}
	})

	t.Run("consent application crash pauses the grant", func(t *testing.T) {
		a := s.request("crash diagnostics")
		conv := s.conversation(a.ID)
		conv.Approve("local-user")
		s.status(a.ID, model.AccessApproved)
		conv.Crash()
		got := s.status(a.ID, model.AccessPaused)
		if got.Reason != proto.ReasonUIGone {
			t.Fatalf("pause reason: %+v", got)
		}
		if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
			t.Fatalf("grant with no consent application allowed a read: %s", text)
		}
		// The service shows the grant again as soon as the application is back.
		waitCtx, cancelWait := context.WithTimeout(ctx, 10*time.Second)
		defer cancelWait()
		back, err := s.script.WaitAfter(waitCtx, a.ID, conv)
		check(t, err)
		back.Resume()
		s.status(a.ID, model.AccessApproved)
		if text, bad := s.read(a.ID); bad || !strings.Contains(text, "acme operational log") {
			t.Fatalf("read after the consent application returned: %s", text)
		}
	})

	// Every transition above is in the client's hash-chained audit log.
	entries := s.entries()
	want := []string{model.AccessRequested, model.AccessAwaiting, model.AccessApproved, model.AccessNarrowed,
		model.AccessActive, model.AccessDenied, model.AccessPaused, model.AccessTerminated}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Kind == audit.KindConsent {
			seen[e.Tool] = true
		}
	}
	for _, state := range want {
		if !seen["access."+state] {
			t.Fatalf("audit is missing consent transition %s", state)
		}
	}
	v, err := s.admin.AuditVerify(ctx, "acme")
	check(t, err)
	if !v.OK || v.Entries == 0 {
		t.Fatalf("audit chain: %+v", v)
	}
}

// TestServiceRestartRevokesLiveGrants proves a grant cannot outlive the
// service that is enforcing it: restarting clears the live grant cache, and
// the restarted service tells the relay so.
func TestServiceRestartRevokesLiveGrants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := newStack(t, ctx)
	a := s.request("restart diagnostics")
	s.conversation(a.ID).Approve("local-user")
	s.status(a.ID, model.AccessApproved)
	if text, bad := s.read(a.ID); bad || !strings.Contains(text, "acme operational log") {
		t.Fatalf("approved read: %s", text)
	}
	s.restart()
	got := s.status(a.ID, model.AccessTerminated)
	if got.Reason != proto.ReasonRestart {
		t.Fatalf("restart termination reason: %+v", got)
	}
	if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("grant survived a service restart: %s", text)
	}
}

// TestRelayEnforcesConsentDeadlineItself proves the consent window is not
// only an endpoint promise: a request nobody has decided is refused by the
// relay too, without asking the machine.
func TestRelayEnforcesConsentDeadlineItself(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := newStack(t, ctx)
	a := s.request("overdue diagnostics")
	conv := s.conversation(a.ID)
	stored, err := s.store.Access(ctx, a.ID)
	check(t, err)
	overdue := time.Now().Add(-time.Second)
	stored.ConsentDeadline = &overdue
	check(t, s.store.UpdateAccess(ctx, stored))
	got := s.status(a.ID, model.AccessDenied)
	if got.Reason != proto.ReasonTimeout {
		t.Fatalf("relay-side timeout reason: %+v", got)
	}
	// A decision that arrives after the refusal cannot revive it: the relay
	// turns it down and says so in the audit log.
	conv.Approve("late-user")
	s.waitAudit("the late approval to be refused", func(e audit.Entry) bool {
		return e.Tool == relay.ConsentRefusedTool && e.RequestID == a.ID
	})
	if final := s.status(a.ID, model.AccessDenied); final.State != model.AccessDenied {
		t.Fatalf("a late approval revived a refused request: %+v", final)
	}
	if text, bad := s.read(a.ID); !bad || !strings.Contains(text, proto.ErrGrantInvalid) {
		t.Fatalf("refused request allowed a read: %s", text)
	}
}

// TestLegacyClientBoundAccessIsUnchanged keeps the deployed migration path
// working: a client-bound session still reads without an access grant.
func TestLegacyClientBoundAccessIsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := newStack(t, ctx)
	text, bad := s.read("")
	if bad || !strings.Contains(text, "acme operational log") {
		t.Fatalf("legacy read: %s", text)
	}
	if len(s.script.Activities()) != 0 {
		t.Fatal("a client-bound call was reported as consented activity")
	}
}

// waitAudit waits for an entry in the client's audit chain that match
// accepts. The audit entry is how a test knows the relay has finished with
// an event whose whole effect is that nothing changed.
func (s *stack) waitAudit(what string, match func(audit.Entry) bool) audit.Entry {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, e := range s.entries() {
			if match(e) {
				return e
			}
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *stack) entries() []audit.Entry {
	s.t.Helper()
	var out []audit.Entry
	check(s.t, s.audit.Range(s.ctx, "acme", time.Time{}, time.Time{}, func(e audit.Entry) error {
		out = append(out, e)
		return nil
	}))
	return out
}
