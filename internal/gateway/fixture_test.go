package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// Bearers in the fixture.
const (
	bearerACME    = "khs_acme_alice"
	bearerGlobex  = "khs_globex_bob"
	bearerExpired = "khs_acme_expired"
	bearerRevoked = "khs_acme_revoked"
	bearerTech    = "oidc_alice"
)

// fakeDir is an in-memory model.Directory that tests can change mid-run.
type fakeDir struct {
	mu       sync.Mutex
	sessions map[string]model.Session // by bearer
	clients  map[string]model.Client
	devices  map[string][]model.Device
	acl      map[string]map[string]bool
	access   map[string]model.AccessRequest
	// txHook, when set, runs once at the start of the next UpdateAccessTx,
	// with the lock held: a test uses it to land a concurrent endpoint
	// decision between the gateway's read of a request and its write.
	txHook func(access map[string]model.AccessRequest, id string)
}

func (d *fakeDir) CreateAccess(_ context.Context, access model.AccessRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.access[access.ID] = access
	return nil
}

func (d *fakeDir) Access(_ context.Context, id string) (model.AccessRequest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	access, ok := d.access[id]
	if !ok {
		return model.AccessRequest{}, fmt.Errorf("access: %w", model.ErrNotFound)
	}
	return access, nil
}

func (d *fakeDir) UpdateAccess(_ context.Context, access model.AccessRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.access[access.ID]; !ok {
		return fmt.Errorf("access: %w", model.ErrNotFound)
	}
	d.access[access.ID] = access
	return nil
}

func (d *fakeDir) UpdateAccessTx(_ context.Context, id string, fn func(*model.AccessRequest) error) (model.AccessRequest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if hook := d.txHook; hook != nil {
		d.txHook = nil
		hook(d.access, id)
	}
	stored, ok := d.access[id]
	if !ok {
		return model.AccessRequest{}, fmt.Errorf("access: %w", model.ErrNotFound)
	}
	next := stored
	if err := fn(&next); err != nil {
		return stored, err
	}
	d.access[id] = next
	return next, nil
}

func (d *fakeDir) ClientsForTechnician(_ context.Context, technician string) ([]model.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []model.Client
	for slug := range d.acl[technician] {
		if client, ok := d.clients[slug]; ok {
			out = append(out, client)
		}
	}
	return out, nil
}

func (d *fakeDir) TechnicianCanAccess(_ context.Context, technician, client string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acl[technician][client], nil
}

type fakeAuthenticator struct {
	sessions map[string]model.TechnicianSession
}

type failingAuthenticator struct{}

func (failingAuthenticator) AuthenticateTechnician(context.Context, string) (model.TechnicianSession, error) {
	return model.TechnicianSession{}, errors.New("identity provider unavailable")
}

func (a fakeAuthenticator) AuthenticateTechnician(_ context.Context, bearer string) (model.TechnicianSession, error) {
	s, ok := a.sessions[bearer]
	if !ok {
		return model.TechnicianSession{}, fmt.Errorf("technician token: %w", model.ErrNotFound)
	}
	return s, nil
}

func (d *fakeDir) SessionByToken(_ context.Context, bearer string) (model.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[bearer]
	if !ok {
		return model.Session{}, fmt.Errorf("session: %w", model.ErrNotFound)
	}
	return s, nil
}

func (d *fakeDir) Client(_ context.Context, slug string) (model.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.clients[slug]
	if !ok {
		return model.Client{}, fmt.Errorf("client %q: %w", slug, model.ErrNotFound)
	}
	return c, nil
}

func (d *fakeDir) Devices(_ context.Context, client string) ([]model.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]model.Device(nil), d.devices[client]...), nil
}

func (d *fakeDir) update(fn func(*fakeDir)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fn(d)
}

type fakeConns map[string]*nats.Conn

func (f fakeConns) Conn(client string) (*nats.Conn, error) {
	nc, ok := f[client]
	if !ok {
		return nil, fmt.Errorf("client %q: %w", client, model.ErrNotFound)
	}
	return nc, nil
}

// fakeAgent answers RPCs for the devices it serves, inside one account, the
// way the real agent does: Result is json.Marshal of the op result and Meta
// covers exactly those bytes.
type fakeAgent struct {
	mu     sync.Mutex
	reqs   []proto.Request
	files  map[string]string // readable path -> content
	tamper bool              // report a wrong SHA-256
	review bool              // behave like an endpoint that shows each plan to the person there
	plans  map[string]fakePlan
	during func(proto.Request) // runs while a request is being handled, before the answer
}

// fakePlan is one staged change, the way the endpoint holds it.
type fakePlan struct {
	path, digest, before, after string
	applied                     bool
}

// change answers the structured remediation ops the way the endpoint does: a
// prepare stages a plan and returns its digest, an apply insists on that exact
// digest, and every one of them refuses a request with no capability naming
// the op.
func (a *fakeAgent) change(req proto.Request, path, content string) (any, *proto.ChangeMeta, *proto.Error) {
	if req.Capability == nil || !slices.Contains(req.Capability.Operations, req.Op) {
		return nil, nil, &proto.Error{Code: proto.ErrConsentRequired, Message: "no capability for " + req.Op}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.plans == nil {
		a.plans = map[string]fakePlan{}
	}
	switch req.Op {
	case proto.OpPrepareFileChange:
		var in proto.PrepareFileChangeArgs
		_ = json.Unmarshal(req.Args, &in)
		p := fakePlan{path: path, digest: "digest-" + sha256Hex([]byte(path + in.Content))[:16],
			before: sha256Hex([]byte(content)), after: sha256Hex([]byte(in.Content))}
		id := "plan_" + p.digest[len("digest-"):]
		a.plans[id] = p
		plan := proto.ChangePlan{PlanID: id, PlanDigest: p.digest, Op: req.Op, Mode: proto.ChangeModeText,
			Before:      proto.FileSnapshot{Path: path, Size: int64(len(content)), SHA256: p.before, ModTime: modTime},
			AfterSHA256: p.after, AfterSize: int64(len(in.Content)), DiffLines: 3,
			Diff: "--- " + path + "\n+++ " + path + "\n@@ -1,1 +1,1 @@\n-" + content + "\n+" + in.Content + "\n"}
		res := proto.PrepareFileChangeResult{ChangePlan: plan}
		if a.review {
			res.Review = "awaiting"
		}
		return res, &proto.ChangeMeta{PlanID: id, PlanDigest: p.digest, BeforeSHA256: p.before, AfterSHA256: p.after}, nil
	case proto.OpApplyFileChange:
		var in proto.ApplyFileChangeArgs
		_ = json.Unmarshal(req.Args, &in)
		p, ok := a.plans[in.PlanID]
		if !ok || p.applied || p.digest != in.PlanDigest {
			return nil, nil, &proto.Error{Code: proto.ErrStalePlan, Message: "unknown, spent or mismatched plan"}
		}
		p.applied = true
		a.plans[in.PlanID] = p
		a.files[p.path] = "applied"
		meta := &proto.ChangeMeta{PlanID: in.PlanID, PlanDigest: p.digest, BeforeSHA256: p.before, AfterSHA256: p.after, BytesChanged: 7}
		if a.review {
			meta.Approver = `ACME\sam`
		}
		return proto.ApplyFileChangeResult{PlanID: in.PlanID, PlanDigest: p.digest, Path: p.path,
			BeforeSHA256: p.before, AfterSHA256: p.after, BytesWritten: 7, RollbackID: "rb_" + in.PlanID[5:]}, meta, nil
	case proto.OpRollbackFileChange:
		var in proto.RollbackFileChangeArgs
		_ = json.Unmarshal(req.Args, &in)
		p, ok := a.plans[in.PlanID]
		if !ok || !p.applied {
			return nil, nil, &proto.Error{Code: proto.ErrStalePlan, Message: "nothing to roll back"}
		}
		return proto.RollbackFileChangeResult{PlanID: in.PlanID, Path: p.path, BeforeSHA256: p.after, AfterSHA256: p.before},
			&proto.ChangeMeta{PlanID: in.PlanID, BeforeSHA256: p.after, AfterSHA256: p.before}, nil
	default:
		var in proto.ServiceRestartArgs
		_ = json.Unmarshal(req.Args, &in)
		if in.Name != "VendorService" {
			return nil, nil, &proto.Error{Code: proto.ErrNotAllowed, Message: "not an allowed service"}
		}
		return proto.ServiceResult{Name: in.Name, State: proto.ServiceRunning, Restarted: req.Op == proto.OpServiceRestart},
			&proto.ChangeMeta{Service: in.Name}, nil
	}
}

func (a *fakeAgent) serve(t *testing.T, nc *nats.Conn, dev model.Device) {
	t.Helper()
	sub, err := nc.Subscribe(proto.RPCWildcard(dev.ID), func(m *nats.Msg) {
		var req proto.Request
		if err := json.Unmarshal(m.Data, &req); err != nil {
			t.Errorf("agent: bad request: %v", err)
			return
		}
		a.mu.Lock()
		a.reqs = append(a.reqs, req)
		during := a.during
		a.mu.Unlock()
		if during != nil {
			during(req)
		}
		b, _ := json.Marshal(a.answer(dev, req))
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
}

func (a *fakeAgent) requests() []proto.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]proto.Request(nil), a.reqs...)
}

var modTime = time.Date(2026, 9, 10, 8, 0, 0, 0, time.UTC)

func (a *fakeAgent) answer(dev model.Device, req proto.Request) proto.Response {
	var args struct {
		Path    string `json:"path"`
		Pattern string `json:"pattern"`
	}
	_ = json.Unmarshal(req.Args, &args)
	meta := proto.Meta{AgentVersion: "v9.9.9-test", AgentTime: time.Now(), RuleID: "test-rule", ResolvedPath: args.Path}
	a.mu.Lock()
	content, readable := a.files[args.Path]
	tamper := a.tamper
	a.mu.Unlock()
	if !readable && req.Op != proto.OpListDir && req.Op != proto.OpSearchFiles &&
		req.Op != proto.OpApplyFileChange && req.Op != proto.OpRollbackFileChange &&
		req.Op != proto.OpServiceQuery && req.Op != proto.OpServiceRestart && req.Op != proto.OpRequestAccess &&
		req.Op != proto.OpListPrinters {
		return proto.Response{V: proto.Version, ID: req.ID, Meta: meta,
			Error: &proto.Error{Code: proto.ErrNotAllowed, Message: "path is outside every allow rule"}}
	}

	var result any
	switch req.Op {
	case proto.OpReadFile:
		meta.Redactions = 1
		result = proto.ReadFileResult{Path: args.Path, Size: int64(len(content)), Length: int64(len(content)),
			Content: content, ModTime: modTime}
	case proto.OpGrep:
		var ms []proto.GrepMatch
		for i, line := range strings.Split(content, "\n") {
			if strings.Contains(line, args.Pattern) {
				ms = append(ms, proto.GrepMatch{Path: args.Path, Line: i + 1, Text: line})
			}
		}
		result = proto.GrepResult{Matches: ms, FilesScanned: 1}
	case proto.OpListDir:
		result = proto.ListDirResult{Path: args.Path, Entries: []proto.FileInfo{
			{Name: "CBS.log", Path: args.Path + `\CBS.log`, Type: proto.TypeFile, Size: 42, ModTime: modTime}}}
	case proto.OpStat:
		result = proto.StatResult{FileInfo: proto.FileInfo{Name: "x", Path: args.Path, Type: proto.TypeFile, Size: int64(len(content)), ModTime: modTime}, Mode: "-rw-r--r--"}
	case proto.OpSearchFiles:
		result = proto.SearchFilesResult{Matches: []proto.FileInfo{{Name: "x", Path: args.Path, Type: proto.TypeFile}}, Scanned: 1}
	case proto.OpHashFile:
		result = proto.HashFileResult{Path: args.Path, Size: int64(len(content)), SHA256: sha256Hex([]byte(content)), ModTime: modTime}
	case proto.OpRequestAccess:
		// The endpoint acknowledges an asynchronous consent request. Gateway
		// tests that need an approved grant seed one explicitly.
		result = proto.ConsentDecision{State: proto.ConsentAwaiting}
	case proto.OpListPrinters:
		result = fakePrinters
	case proto.OpPrepareFileChange, proto.OpApplyFileChange, proto.OpRollbackFileChange,
		proto.OpServiceQuery, proto.OpServiceRestart:
		var cerr *proto.Error
		result, meta.Change, cerr = a.change(req, args.Path, content)
		if cerr != nil {
			return proto.Response{V: proto.Version, ID: req.ID, Meta: meta, Error: cerr}
		}
	default:
		return proto.Response{V: proto.Version, ID: req.ID, Meta: meta, Error: &proto.Error{Code: proto.ErrUnsupported, Message: req.Op}}
	}
	raw, _ := json.Marshal(result)
	meta.Bytes, meta.SHA256 = int64(len(raw)), sha256Hex(raw)
	if tamper {
		meta.SHA256 = strings.Repeat("0", 64)
	}
	return proto.Response{V: proto.Version, ID: req.ID, OK: true, Result: raw, Meta: meta}
}

// fixture is a running gateway over an embedded nats-server with two client
// accounts, ACME and GLOBEX, each with its own agent.
type fixture struct {
	now    time.Time
	dir    *fakeDir
	store  *audit.MemStore
	acme   *fakeAgent // serves ACME's SRV01 and web01
	globex *fakeAgent // serves GLOBEX's DC01
	url    string
}

func startNATS(t *testing.T, accounts ...string) *server.Server {
	t.Helper()
	var accts strings.Builder
	for _, a := range accounts {
		fmt.Fprintf(&accts, "  %s: {users: [{user: %q, password: %q}]}\n", strings.ToUpper(a), a, "pw-"+a)
	}
	opts := &server.Options{}
	if err := opts.ProcessConfigString(fmt.Sprintf("listen: 127.0.0.1:-1\nmax_payload: 8MB\naccounts: {\n%s}\n", accts.String())); err != nil {
		t.Fatal(err)
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(func() { s.Shutdown(); s.WaitForShutdown() })
	return s
}

func connectAs(t *testing.T, s *server.Server, account string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(account, "pw-"+account))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func device(id, client, host, goos string, lastSeen time.Time) model.Device {
	return model.Device{ID: id, Client: client, PublicKey: "U" + strings.ToUpper(id), Hostname: host, OS: goos,
		OSVersion: "test", AgentVersion: "v0.0.1", EnrolledAt: lastSeen.Add(-time.Hour), LastSeen: &lastSeen}
}

func newFixture(t *testing.T, tweak ...func(*Config)) *fixture {
	t.Helper()
	now := time.Now()
	recent, stale := now.Add(-10*time.Second), now.Add(-10*time.Minute)
	revokedAt := now.Add(-time.Hour)
	oldSRV01 := device("dev_acme_old", "acme", "SRV01", "windows", stale)
	oldSRV01.RevokedAt, oldSRV01.EnrolledAt = &revokedAt, now.Add(-48*time.Hour)
	gone := device("dev_acme_gone", "acme", "GONE01", "windows", stale)
	gone.RevokedAt = &revokedAt

	f := &fixture{
		now:   now,
		store: audit.NewMemStore(),
		acme:  &fakeAgent{files: map[string]string{`C:\Windows\Logs\CBS\CBS.log`: "line one\nerror: disk full\nline three\n", "/var/log/syslog": "boot ok\n"}},
		globex: &fakeAgent{files: map[string]string{
			`C:\Windows\Logs\CBS\CBS.log`: "GLOBEX SECRET LOG\n"}},
	}
	f.dir = &fakeDir{
		sessions: map[string]model.Session{
			bearerACME:    {ID: "ses_alice", Client: "acme", Tech: "alice@msp", ExpiresAt: now.Add(time.Hour)},
			bearerGlobex:  {ID: "ses_bob", Client: "globex", Tech: "bob@msp", ExpiresAt: now.Add(time.Hour)},
			bearerExpired: {ID: "ses_old", Client: "acme", Tech: "alice@msp", ExpiresAt: now.Add(-time.Minute)},
			bearerRevoked: {ID: "ses_rev", Client: "acme", Tech: "alice@msp", ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt},
		},
		clients: map[string]model.Client{
			"acme":   {Slug: "acme", Name: "ACME Corp", Policy: policy.DefaultClientPolicy()},
			"globex": {Slug: "globex", Name: "Globex", Policy: policy.DefaultClientPolicy()},
		},
		devices: map[string][]model.Device{
			"acme": {
				oldSRV01,
				device("dev_acme_srv01", "acme", "SRV01", "windows", recent),
				device("dev_acme_web01", "acme", "web01", "linux", recent),
				device("dev_acme_off", "acme", "OLD01", "windows", stale),
				device("dev_acme_ghost", "acme", "GHOST01", "windows", recent), // "online" but no agent connected
				device("dev_acme_dup1", "acme", "dup", "linux", recent),
				device("dev_acme_dup2", "acme", "DUP", "linux", recent),
				gone,
			},
			"globex": {device("dev_globex_dc01", "globex", "GLOBEX-DC01", "windows", recent)},
		},
		acl:    map[string]map[string]bool{"tech_alice": {"acme": true}},
		access: map[string]model.AccessRequest{},
	}

	ns := startNATS(t, "acme", "globex")
	conns := fakeConns{"acme": connectAs(t, ns, "acme"), "globex": connectAs(t, ns, "globex")}
	acmeAgentConn, globexAgentConn := connectAs(t, ns, "acme"), connectAs(t, ns, "globex")
	for _, d := range f.dir.devices["acme"] {
		if d.ID == "dev_acme_srv01" || d.ID == "dev_acme_web01" {
			f.acme.serve(t, acmeAgentConn, d)
		}
	}
	f.globex.serve(t, globexAgentConn, f.dir.devices["globex"][0])

	cfg := Config{Directory: f.dir, TechnicianACL: f.dir, Conns: conns, Audit: f.store, Access: f.dir, Now: func() time.Time { return f.now }, RPCTimeout: 5 * time.Second}
	for _, fn := range tweak {
		fn(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// connect opens an MCP session the way Claude Code does, with a static bearer.
func (f *fixture) connect(t *testing.T, bearer string) *mcp.ClientSession {
	t.Helper()
	cs, err := f.dial(bearer)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (f *fixture) dial(bearer string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "keyhole-test", Version: "v0"}, nil)
	return client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             f.url,
		HTTPClient:           &http.Client{Transport: bearerTransport{bearer}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
}

// call runs a tool and returns its text and whether it was a tool error.
func call(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", tool, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func (f *fixture) entries(t *testing.T, client string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	if err := f.store.Range(context.Background(), client, time.Time{}, time.Time{}, func(e audit.Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) lastEntry(t *testing.T, client string) audit.Entry {
	t.Helper()
	es := f.entries(t, client)
	if len(es) == 0 {
		t.Fatalf("no audit entries for %s", client)
	}
	return es[len(es)-1]
}
