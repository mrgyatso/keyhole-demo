package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nats-io/nats.go"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

// The change gate's fixture: a gateway with technician approval on, over the
// relay's real store (change plans and approvals hang off real access rows),
// an embedded nats-server, and a Slice 6 endpoint for the change ops.

const (
	gateBearerLegacy = "khs_acme_gate"   // a client-bound session of alice@msp in acme
	gateBearerGlobex = "khs_globex_gate" // the same technician name, bound to globex
	gateBearerAlice  = "oidc_gate_alice" // the technician tech_alice
	gateBearerBob    = "oidc_gate_bob"   // the technician tech_bob, also assigned acme
	gateCompanion    = "https://companion.example"
	gateDevice       = "dev_acme_srv01"
	gateFile         = `C:\ProgramData\Vendor\config.json`
	gateOriginal     = `{"retries": 1}`
)

// gateClock is the fixture's clock, which tests move on. The gateway reads it
// from its own goroutines, so it is locked.
type gateClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *gateClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *gateClock) add(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// gateDir is the fixture directory plus the relay store's session lookup, so
// a release can see that a client-bound session was revoked.
type gateDir struct{ *fakeDir }

func (d gateDir) Session(_ context.Context, id string) (model.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return model.Session{}, fmt.Errorf("session %q: %w", id, model.ErrNotFound)
}

// gateEndpoint is a Slice 6 endpoint for the change ops, the way the endpoint
// build is specified: a prepare stages a plan; an apply or rollback needs a
// signed technician approval of exactly that op, plan and grant; and a request
// ID it has already applied is answered from its journal with the first
// result, so a repeated release never writes twice.
type gateEndpoint struct {
	t      *testing.T
	now    func() time.Time
	nc     *nats.Conn
	device string

	mu      sync.Mutex
	sub     *nats.Subscription
	reqs    []proto.Request
	files   map[string]string
	plans   map[string]*gatePlan
	journal map[string]proto.Response // completed writes, by request ID
	writes  int                       // times a file was actually written
	refuse  string                    // refuse every apply and rollback with this code
	drop    bool                      // make the next change but never answer
	during  func(proto.Request)       // runs while a request is handled, before the answer
}

// gatePlan is one staged change, the way the endpoint holds it.
type gatePlan struct {
	id, digest, path, before, after, rollbackID string
	expires                                     time.Time
	applied                                     bool
}

// online connects the endpoint's agent; offline disconnects it, so the
// relay's requests find no responder.
func (ep *gateEndpoint) online(t *testing.T) {
	t.Helper()
	sub, err := ep.nc.Subscribe(proto.RPCWildcard(ep.device), ep.handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ep.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	ep.mu.Lock()
	ep.sub = sub
	ep.mu.Unlock()
}

func (ep *gateEndpoint) offline(t *testing.T) {
	t.Helper()
	ep.mu.Lock()
	sub := ep.sub
	ep.sub = nil
	ep.mu.Unlock()
	if sub == nil {
		return
	}
	if err := sub.Unsubscribe(); err != nil {
		t.Fatal(err)
	}
	if err := ep.nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

func (ep *gateEndpoint) handle(m *nats.Msg) {
	var req proto.Request
	if err := json.Unmarshal(m.Data, &req); err != nil {
		ep.t.Errorf("endpoint: bad request: %v", err)
		return
	}
	ep.mu.Lock()
	ep.reqs = append(ep.reqs, req)
	during := ep.during
	ep.mu.Unlock()
	if during != nil {
		during(req)
	}
	resp, answer := ep.answer(req)
	if !answer {
		return
	}
	b, _ := json.Marshal(resp)
	_ = m.Respond(b)
}

func (ep *gateEndpoint) answer(req proto.Request) (proto.Response, bool) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	c := req.Capability
	if c == nil || !slices.Contains(c.Operations, req.Op) {
		return gateRefusal(req, proto.ErrConsentRequired, "no capability for "+req.Op), true
	}
	if prev, ok := ep.journal[req.ID]; ok {
		return prev, true
	}
	now := ep.now()
	switch req.Op {
	case proto.OpPrepareFileChange:
		var in proto.PrepareFileChangeArgs
		if err := json.Unmarshal(req.Args, &in); err != nil {
			return gateRefusal(req, proto.ErrBadRequest, err.Error()), true
		}
		before, ok := ep.files[in.Path]
		if !ok {
			return gateRefusal(req, proto.ErrNotAllowed, "path is outside every allow rule"), true
		}
		p := &gatePlan{id: model.NewID("plan"), path: in.Path, before: before, after: in.Content, expires: now.Add(proto.ChangePlanTTL)}
		p.digest = "digest-" + sha256Hex([]byte(p.id + in.Content))[:16]
		if c.ExpiresAt.Before(p.expires) {
			p.expires = c.ExpiresAt // a plan never outlives the grant that prepared it
		}
		ep.plans[p.id] = p
		plan := proto.ChangePlan{PlanID: p.id, PlanDigest: p.digest, Op: req.Op, Mode: proto.ChangeModeText, Reason: in.Reason,
			Before:      proto.FileSnapshot{Path: in.Path, Size: int64(len(before)), SHA256: sha256Hex([]byte(before))},
			AfterSHA256: sha256Hex([]byte(in.Content)), AfterSize: int64(len(in.Content)), DiffLines: 2,
			Diff: "-" + before + "\n+" + in.Content + "\n", PreparedAt: now, ExpiresAt: p.expires}
		return gateResult(req, proto.PrepareFileChangeResult{ChangePlan: plan}, &proto.ChangeMeta{PlanID: p.id, PlanDigest: p.digest}), true

	case proto.OpApplyFileChange:
		var in proto.ApplyFileChangeArgs
		_ = json.Unmarshal(req.Args, &in)
		if why := gateCheckApproval(req, in.Approval, in.PlanID, in.PlanDigest, "", now); why != "" {
			return gateRefusal(req, proto.ErrApprovalRequired, why), true
		}
		if ep.refuse != "" {
			return gateRefusal(req, ep.refuse, "refused by the test"), true
		}
		p := ep.plans[in.PlanID]
		switch {
		case p == nil || p.applied || p.digest != in.PlanDigest:
			return gateRefusal(req, proto.ErrStalePlan, "unknown, spent or mismatched plan"), true
		case ep.files[p.path] != p.before:
			return gateRefusal(req, proto.ErrStalePlan, "the file changed after review"), true
		}
		ep.files[p.path], p.applied, p.rollbackID = p.after, true, "rb_"+p.id
		ep.writes++
		return ep.commit(req, gateResult(req,
			proto.ApplyFileChangeResult{PlanID: p.id, PlanDigest: p.digest, Path: p.path, BeforeSHA256: sha256Hex([]byte(p.before)),
				AfterSHA256: sha256Hex([]byte(p.after)), BytesWritten: int64(len(p.after)), RollbackID: p.rollbackID, AppliedAt: now},
			&proto.ChangeMeta{PlanID: p.id, PlanDigest: p.digest, Approver: in.Approval.ApproverLabel(), ApprovalID: in.Approval.ID,
				BeforeSHA256: sha256Hex([]byte(p.before)), AfterSHA256: sha256Hex([]byte(p.after)), BytesChanged: int64(len(p.after))}))

	case proto.OpRollbackFileChange:
		var in proto.RollbackFileChangeArgs
		_ = json.Unmarshal(req.Args, &in)
		p := ep.plans[in.PlanID]
		digest := ""
		if p != nil {
			digest = p.digest
		}
		if why := gateCheckApproval(req, in.Approval, in.PlanID, digest, in.RollbackID, now); why != "" {
			return gateRefusal(req, proto.ErrApprovalRequired, why), true
		}
		if ep.refuse != "" {
			return gateRefusal(req, ep.refuse, "refused by the test"), true
		}
		switch {
		case p == nil || !p.applied || (in.RollbackID != "" && in.RollbackID != p.rollbackID):
			return gateRefusal(req, proto.ErrStalePlan, "nothing to roll back"), true
		case ep.files[p.path] != p.after:
			return gateRefusal(req, proto.ErrStalePlan, "the file no longer holds what the apply wrote"), true
		}
		ep.files[p.path], p.applied = p.before, false
		ep.writes++
		return ep.commit(req, gateResult(req,
			proto.RollbackFileChangeResult{PlanID: p.id, Path: p.path, BeforeSHA256: sha256Hex([]byte(p.after)),
				AfterSHA256: sha256Hex([]byte(p.before)), BytesWritten: int64(len(p.before)), RestoredAt: now},
			&proto.ChangeMeta{PlanID: p.id, Approver: in.Approval.ApproverLabel(), ApprovalID: in.Approval.ID}))
	}
	return gateRefusal(req, proto.ErrUnsupported, req.Op), true
}

// commit journals a completed write under its request ID and answers it,
// unless the test drops the answer.
func (ep *gateEndpoint) commit(req proto.Request, resp proto.Response) (proto.Response, bool) {
	ep.journal[req.ID] = resp
	if ep.drop {
		ep.drop = false
		return resp, false
	}
	return resp, true
}

// gateCheckApproval is the endpoint's check of a change's technician
// approval: a signed change approval of exactly this op, plan and rollback,
// for the grant the request's capability carries, and unexpired. It says what
// is wrong, or "".
func gateCheckApproval(req proto.Request, a *proto.TechnicianApproval, planID, digest, rollbackID string, now time.Time) string {
	c := req.Capability
	switch {
	case a == nil:
		return "the change carries no technician approval"
	case a.Kind != proto.ApprovalChange || a.Op != req.Op || !a.Signed() || a.ID == "" || a.Nonce == "":
		return "not a signed change approval of " + req.Op
	case a.Technician != c.Technician || a.Client != c.Client || a.Device != c.Device || a.AccessID != c.AccessID || a.GrantID != c.GrantID:
		return "the approval is for another grant"
	case a.PlanID != planID || a.PlanDigest != digest || a.RollbackID != rollbackID:
		return "the approval is for another plan"
	case !now.Before(a.ExpiresAt.Add(proto.ApprovalClockSkew)):
		return "the approval has expired"
	}
	return ""
}

func gateResult(req proto.Request, result any, change *proto.ChangeMeta) proto.Response {
	raw, _ := json.Marshal(result)
	return proto.Response{V: proto.Version, ID: req.ID, OK: true, Result: raw, Meta: proto.Meta{Bytes: int64(len(raw)),
		SHA256: sha256Hex(raw), AgentTime: time.Now(), AgentVersion: "v9.9.9-test", Change: change}}
}

func gateRefusal(req proto.Request, code, msg string) proto.Response {
	return proto.Response{V: proto.Version, ID: req.ID, Meta: proto.Meta{AgentTime: time.Now(), AgentVersion: "v9.9.9-test"},
		Error: &proto.Error{Code: code, Message: msg}}
}

// requests returns the requests the endpoint received for op, or all of them
// for "".
func (ep *gateEndpoint) requests(op string) []proto.Request {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	var out []proto.Request
	for _, r := range ep.reqs {
		if op == "" || r.Op == op {
			out = append(out, r)
		}
	}
	return out
}

func (ep *gateEndpoint) set(fn func(*gateEndpoint)) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	fn(ep)
}

func (ep *gateEndpoint) file() string {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.files[gateFile]
}

func (ep *gateEndpoint) writeCount() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.writes
}

// gateFixture is a gateway with technician approval on.
type gateFixture struct {
	clock *gateClock
	dir   *fakeDir
	st    *store.Store
	log   *audit.MemStore
	ep    *gateEndpoint
	g     *Gateway
	url   string
}

func newGateFixture(t *testing.T, tweak ...func(*Config)) *gateFixture {
	t.Helper()
	ctx := context.Background()
	start := time.Now().UTC()
	f := &gateFixture{clock: &gateClock{t: start}, log: audit.NewMemStore()}

	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.st = st
	for _, slug := range []string{"acme", "globex"} {
		keys := store.AccountKeys{AccountKey: "A-" + slug, AccountSeed: "SA-" + slug, SigningSeed: "SS-" + slug,
			AccountJWT: "jwt-" + slug, RelayJWT: "relay-jwt-" + slug, RelaySeed: "SU-" + slug}
		if err := st.CreateClient(ctx, model.Client{Slug: slug, Name: slug, CreatedAt: start, Policy: policy.DefaultClientPolicy()}, keys); err != nil {
			t.Fatal(err)
		}
	}
	secret := model.NewEnrollSecret("acme")
	if err := st.CreateToken(ctx, model.EnrollToken{ID: model.NewID(model.PrefixToken), Client: "acme",
		Hash: model.HashSecret(secret), CreatedAt: start, ExpiresAt: start.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	acme := []model.Device{device(gateDevice, "acme", "SRV01", "windows", start), device("dev_acme_web01", "acme", "web01", "windows", start)}
	for _, d := range acme {
		if _, err := st.EnrollDevice(ctx, store.EnrollParams{Secret: secret, Device: d, Now: start}); err != nil {
			t.Fatal(err)
		}
	}
	for cred, tech := range map[string]string{"cred-alice": "tech_alice", "cred-alice-old": "tech_alice", "cred-bob": "tech_bob", "cred-legacy": "alice@msp"} {
		link := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: tech, Hash: model.HashSecret(cred + "-link"),
			CreatedAt: start, ExpiresAt: start.Add(model.PasskeyLinkTTL)}
		if err := st.CreatePasskeyLink(ctx, link); err != nil {
			t.Fatal(err)
		}
		if err := st.UsePasskeyLink(ctx, link.ID, model.Passkey{CredentialID: cred, Technician: tech, PublicKey: []byte{1},
			Algorithm: -7, Name: cred}, start); err != nil {
			t.Fatal(err)
		}
	}

	life := start.Add(48 * time.Hour)
	f.dir = &fakeDir{
		sessions: map[string]model.Session{
			gateBearerLegacy: {ID: "ses_gate", Client: "acme", Tech: "alice@msp", ExpiresAt: life},
			gateBearerGlobex: {ID: "ses_gate_globex", Client: "globex", Tech: "alice@msp", ExpiresAt: life},
		},
		clients: map[string]model.Client{
			"acme":   {Slug: "acme", Name: "ACME Corp", Policy: policy.DefaultClientPolicy()},
			"globex": {Slug: "globex", Name: "Globex", Policy: policy.DefaultClientPolicy()},
		},
		devices: map[string][]model.Device{"acme": acme, "globex": {device("dev_globex_dc01", "globex", "DC01", "windows", start)}},
		acl:     map[string]map[string]bool{"tech_alice": {"acme": true}, "tech_bob": {"acme": true}},
		access:  map[string]model.AccessRequest{},
	}

	ns := startNATS(t, "acme", "globex")
	conns := fakeConns{"acme": connectAs(t, ns, "acme"), "globex": connectAs(t, ns, "globex")}
	f.ep = &gateEndpoint{t: t, now: f.clock.now, nc: connectAs(t, ns, "acme"), device: gateDevice,
		files: map[string]string{gateFile: gateOriginal}, plans: map[string]*gatePlan{}, journal: map[string]proto.Response{}}
	f.ep.online(t)

	auth := fakeAuthenticator{sessions: map[string]model.TechnicianSession{
		gateBearerAlice: {ID: "idp_gate_alice", Technician: "tech_alice", Name: "Alice", MFA: true, ExpiresAt: life},
		gateBearerBob:   {ID: "idp_gate_bob", Technician: "tech_bob", Name: "Bob", MFA: true, ExpiresAt: life},
	}}
	cfg := Config{Directory: gateDir{f.dir}, TechnicianACL: f.dir, Authenticator: auth, Conns: conns, Audit: f.log,
		Access: st, Approvals: st, CompanionURL: gateCompanion + "/", Now: f.clock.now, RPCTimeout: 2 * time.Second}
	for _, fn := range tweak {
		fn(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.g = g
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *gateFixture) connect(t *testing.T, bearer string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "keyhole-test", Version: "v0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             f.url,
		HTTPClient:           &http.Client{Transport: bearerTransport{bearer}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// advance moves the clock on. The machines keep reporting in, so the relay
// still counts them online; a test takes the endpoint offline itself.
func (f *gateFixture) advance(d time.Duration) {
	now := f.clock.add(d)
	f.dir.update(func(dir *fakeDir) {
		for _, devs := range dir.devices {
			for i := range devs {
				seen := now
				devs[i].LastSeen = &seen
			}
		}
	})
}

// grant stores an approved access grant of tech's on the fixture's device.
func (f *gateFixture) grant(t *testing.T, tech, session string, life time.Duration, ops ...string) model.AccessRequest {
	t.Helper()
	now := f.clock.now()
	decided := now.Add(-time.Minute)
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: "acme", Device: gateDevice, Technician: tech,
		Session: session, Purpose: "fix the vendor agent", State: model.AccessApproved,
		RequestedScope: []string{`C:\ProgramData\Vendor`}, EffectiveScope: []string{`C:\ProgramData\Vendor`},
		RequestedOperations: ops, EffectiveOperations: ops, RequestedAt: decided, DecidedAt: &decided,
		ExpiresAt: now.Add(life), IdleTimeout: time.Hour, GrantID: model.NewID(model.PrefixGrant),
		Nonce: model.NewSecret("gnc"), PolicyVersion: 1}
	if err := f.st.CreateAccess(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *gateFixture) access(t *testing.T, id string) model.AccessRequest {
	t.Helper()
	a, err := f.st.Access(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// prepare prepares content for the fixture's file under a and returns the
// plan.
func (f *gateFixture) prepare(t *testing.T, cs *mcp.ClientSession, a model.AccessRequest, content string) (planID, digest string) {
	t.Helper()
	text, isErr := call(t, cs, proto.OpPrepareFileChange, map[string]any{"device": gateDevice, "access_id": a.ID,
		"path": gateFile, "content": content, "reason": "ticket 42"})
	if isErr {
		t.Fatalf("prepare: %s", text)
	}
	return planFrom(t, text)
}

// submit calls apply_file_change or rollback_file_change and returns the
// submission it answers.
func (f *gateFixture) submit(t *testing.T, cs *mcp.ClientSession, op string, args map[string]any) ChangeSubmission {
	t.Helper()
	text, isErr := call(t, cs, op, args)
	if isErr {
		t.Fatalf("%s: %s", op, text)
	}
	var sub ChangeSubmission
	if err := json.Unmarshal([]byte(text), &sub); err != nil {
		t.Fatalf("%s answered %q: %v", op, text, err)
	}
	return sub
}

func (f *gateFixture) apply(t *testing.T, cs *mcp.ClientSession, a model.AccessRequest, planID, digest string) ChangeSubmission {
	t.Helper()
	return f.submit(t, cs, proto.OpApplyFileChange, map[string]any{"device": gateDevice, "access_id": a.ID,
		"plan_id": planID, "plan_digest": digest})
}

func (f *gateFixture) row(t *testing.T, id string) model.ChangeApproval {
	t.Helper()
	c, err := f.st.ChangeApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sign is what the companion hands the gate once a passkey assertion over
// row's approval has verified: the approval, with who signed it and when.
func (f *gateFixture) sign(row model.ChangeApproval, cred string) proto.TechnicianApproval {
	a := row.Approval()
	a.Credential, a.ApprovedAt = cred, f.clock.now().UTC()
	a.Assertion = &proto.PasskeyAssertion{CredentialID: cred, AuthenticatorData: []byte("authenticator-data"),
		ClientDataJSON: []byte(`{"type":"webauthn.get"}`), Signature: []byte("signature")}
	return a
}

func (f *gateFixture) approve(t *testing.T, id, cred string) model.ChangeApproval {
	t.Helper()
	got, err := f.g.ApproveChange(context.Background(), id, f.sign(f.row(t, id), cred))
	if err != nil {
		t.Fatalf("ApproveChange: %v", err)
	}
	return got
}

func (f *gateFixture) entries(t *testing.T, client string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	if err := f.log.Range(context.Background(), client, time.Time{}, time.Time{}, func(e audit.Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// consent is the audit entry of a change approval's move to state.
func (f *gateFixture) consent(t *testing.T, approvalID, state string) (audit.Entry, bool) {
	t.Helper()
	for _, e := range f.entries(t, "acme") {
		if e.Kind == audit.KindConsent && e.RequestID == approvalID && e.Tool == "change."+state {
			return e, true
		}
	}
	return audit.Entry{}, false
}

// releases are the tool-call audit entries of the releases with requestID.
func (f *gateFixture) releases(t *testing.T, requestID string) []audit.Entry {
	t.Helper()
	var out []audit.Entry
	for _, e := range f.entries(t, "acme") {
		if e.Kind == audit.KindTool && e.RequestID == requestID {
			out = append(out, e)
		}
	}
	return out
}

func gateStatus(t *testing.T, cs *mcp.ClientSession, id string) ChangeStatus {
	t.Helper()
	text, isErr := call(t, cs, ToolChangeStatus, map[string]any{"approval_id": id})
	if isErr {
		t.Fatalf("change_status: %s", text)
	}
	var st ChangeStatus
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		t.Fatalf("change_status answered %q: %v", text, err)
	}
	return st
}
