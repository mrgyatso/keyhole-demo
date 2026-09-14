package companion_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/companion"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/passkey/passkeytest"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

const (
	origin     = "https://keyhole.test"
	rpID       = "keyhole.test"
	alice      = "idp|alice"
	bob        = "idp|bob"
	cookieName = "keyhole_companion"
	csp        = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	beforeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	afterHash  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	planPath   = `C:\ProgramData\Vendor\config.json`
	diffText   = "--- a/config.json\n+++ b/config.json\n@@ -1,2 +1,2 @@\n-\"mode\": \"old\"\n+\"mode\": \"new\"\n <script>alert(1)</script>\n"
)

var bg = context.Background()

// syncBuffer is a log sink the server writes to from its handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// gateCall is one call the companion made to the gate.
type gateCall struct {
	Method     string
	ID         string
	Technician string
	Credential string
	Reason     string
	Approval   proto.TechnicianApproval
}

// fakeGate stands in for the gateway, which B1 and B2 build: it records every
// call, and makes the store transition the real gate would so the cards
// follow.
type fakeGate struct {
	st  *store.Store
	now func() time.Time

	mu     sync.Mutex
	calls  []gateCall
	err    error
	result json.RawMessage
}

func (g *fakeGate) record(c gateCall) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, c)
	return g.err
}

func (g *fakeGate) Calls(method string) []gateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []gateCall
	for _, c := range g.calls {
		if method == "" || c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (g *fakeGate) setErr(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = err
}

func (g *fakeGate) setResult(r string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.result = json.RawMessage(r)
}

func (g *fakeGate) ApproveUnlock(ctx context.Context, id string, a proto.TechnicianApproval) (model.Unlock, error) {
	if err := g.record(gateCall{Method: "ApproveUnlock", ID: id, Technician: a.Technician, Credential: a.Credential, Approval: a}); err != nil {
		return model.Unlock{}, err
	}
	u, _, err := g.st.ActivateUnlockTx(ctx, id, func(u *model.Unlock) error {
		if u.State != model.UnlockAwaiting || !a.SameSigned(u.Approval()) {
			return fmt.Errorf("fake gate: unlock %s: %w", id, model.ErrConflict)
		}
		at := a.ApprovedAt
		u.State, u.DecidedAt, u.Credential = model.UnlockActive, &at, a.Credential
		u.Assertion, _ = json.Marshal(a.Assertion)
		return nil
	}, g.now())
	return u, err
}

func (g *fakeGate) endUnlock(ctx context.Context, id, state, reason, credential string) (model.Unlock, error) {
	return g.st.UpdateUnlockTx(ctx, id, func(u *model.Unlock) error {
		if !model.UnlockAdvance(u.State, state) {
			return fmt.Errorf("fake gate: unlock %s is %s: %w", id, u.State, model.ErrConflict)
		}
		ended := g.now().UTC()
		u.State, u.Reason, u.EndedAt = state, reason, &ended
		if credential != "" {
			u.Credential = credential
		}
		return nil
	})
}

func (g *fakeGate) DenyUnlock(ctx context.Context, id, technician, credential string) (model.Unlock, error) {
	if err := g.record(gateCall{Method: "DenyUnlock", ID: id, Technician: technician, Credential: credential}); err != nil {
		return model.Unlock{}, err
	}
	return g.endUnlock(ctx, id, model.UnlockDenied, model.ReasonDenied, credential)
}

func (g *fakeGate) Lock(ctx context.Context, id, technician, reason string) (model.Unlock, error) {
	if err := g.record(gateCall{Method: "Lock", ID: id, Technician: technician, Reason: reason}); err != nil {
		return model.Unlock{}, err
	}
	return g.endUnlock(ctx, id, model.UnlockLocked, reason, "")
}

func (g *fakeGate) LockAll(ctx context.Context, technician, reason string) error {
	if err := g.record(gateCall{Method: "LockAll", Technician: technician, Reason: reason}); err != nil {
		return err
	}
	list, err := g.st.Unlocks(ctx, technician, time.Time{})
	if err != nil {
		return err
	}
	for _, u := range list {
		if u.State == model.UnlockAwaiting || u.State == model.UnlockActive {
			if _, err := g.endUnlock(ctx, u.ID, model.UnlockLocked, reason, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *fakeGate) ApproveChange(ctx context.Context, id string, a proto.TechnicianApproval) (model.ChangeApproval, error) {
	if err := g.record(gateCall{Method: "ApproveChange", ID: id, Technician: a.Technician, Credential: a.Credential, Approval: a}); err != nil {
		return model.ChangeApproval{}, err
	}
	g.mu.Lock()
	result := g.result
	g.mu.Unlock()
	return g.st.UpdateChangeApprovalTx(ctx, id, func(c *model.ChangeApproval) error {
		if c.State != model.ChangeAwaiting || !a.SameSigned(c.Approval()) {
			return fmt.Errorf("fake gate: change %s: %w", id, model.ErrConflict)
		}
		decided, done := a.ApprovedAt, g.now().UTC()
		c.State, c.DecidedAt, c.CompletedAt, c.Credential = model.ChangeApplied, &decided, &done, a.Credential
		c.Assertion, _ = json.Marshal(a.Assertion)
		c.Result = result
		return nil
	})
}

func (g *fakeGate) DenyChange(ctx context.Context, id, technician, credential string) (model.ChangeApproval, error) {
	if err := g.record(gateCall{Method: "DenyChange", ID: id, Technician: technician, Credential: credential}); err != nil {
		return model.ChangeApproval{}, err
	}
	return g.st.UpdateChangeApprovalTx(ctx, id, func(c *model.ChangeApproval) error {
		if c.State != model.ChangeAwaiting {
			return fmt.Errorf("fake gate: change %s is %s: %w", id, c.State, model.ErrConflict)
		}
		at := g.now().UTC()
		c.State, c.Reason, c.DecidedAt, c.CompletedAt, c.Credential = model.ChangeDenied, model.ReasonDenied, &at, &at, credential
		return nil
	})
}

// harness is a companion on a real store in a temporary directory, with two
// clients (acme with one enrolled device, and globex), a fake gate, and a
// clock the test moves.
type harness struct {
	t      *testing.T
	st     *store.Store
	gate   *fakeGate
	srv    *httptest.Server
	logs   *syncBuffer
	origin string
	rpID   string
	device model.Device // SRV-ACME-01, in acme

	mu  sync.Mutex
	now time.Time
}

func newHarness(t *testing.T) *harness { return newHarnessAt(t, origin) }

func newHarnessAt(t *testing.T, org string) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "keyhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, err := url.Parse(org)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, logs: &syncBuffer{}, origin: org, rpID: u.Hostname(),
		now: time.Date(2026, 9, 11, 14, 0, 0, 0, time.UTC)}
	h.gate = &fakeGate{st: st, now: h.clock}
	for _, c := range []struct{ slug, name string }{{"acme", "Acme Corp"}, {"globex", "Globex"}} {
		keys := store.AccountKeys{AccountKey: "A-" + c.slug, AccountSeed: "SA-" + c.slug, SigningSeed: "SS-" + c.slug,
			AccountJWT: "jwt-" + c.slug, RelayJWT: "relay-jwt-" + c.slug, RelaySeed: "SU-" + c.slug}
		if err := st.CreateClient(bg, model.Client{Slug: c.slug, Name: c.name, CreatedAt: h.now, Policy: policy.DefaultClientPolicy()}, keys); err != nil {
			t.Fatal(err)
		}
	}
	secret := model.NewEnrollSecret("acme")
	tok := model.EnrollToken{ID: model.NewID(model.PrefixToken), Client: "acme", Hash: model.HashSecret(secret),
		CreatedAt: h.now, ExpiresAt: h.now.Add(24 * time.Hour)}
	if err := st.CreateToken(bg, tok); err != nil {
		t.Fatal(err)
	}
	enr, err := st.EnrollDevice(bg, store.EnrollParams{Secret: secret, Now: h.now, Device: model.Device{
		ID: model.NewID(model.PrefixDevice), PublicKey: "U-SRV-ACME-01", Hostname: "SRV-ACME-01", MachineID: "m-1",
		OS: "windows", OSVersion: "10.0.26100", Arch: "amd64", AgentVersion: "v0.1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	h.device = enr.Device
	srv, err := companion.New(companion.Config{Store: st, Directory: st, Gate: h.gate, Origin: org, Now: h.clock,
		Logger: slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = httptest.NewServer(srv.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

type reply struct {
	status int
	body   []byte
	header http.Header
}

func (r reply) code() string {
	var e proto.HTTPError
	_ = json.Unmarshal(r.body, &e)
	return e.Error.Code
}

func (r reply) cookie() *http.Cookie {
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

// send makes a request the way the companion's own page does: with its
// Origin and a JSON body on anything but GET, and with the sign-in cookie
// when secret is set. edit changes the request before it is sent.
func (h *harness) send(method, path, secret string, body any, edit ...func(*http.Request)) reply {
	h.t.Helper()
	var rd io.Reader
	if method != http.MethodGet {
		var b []byte
		switch v := body.(type) {
		case nil:
			b = []byte("{}")
		case []byte:
			b = v
		case string:
			b = []byte(v)
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				h.t.Fatal(err)
			}
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", h.origin)
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: secret})
	}
	for _, e := range edit {
		e(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return reply{resp.StatusCode, data, resp.Header}
}

func (h *harness) get(path, secret string) reply {
	h.t.Helper()
	return h.send(http.MethodGet, path, secret, nil)
}

func (h *harness) post(path, secret string, body any) reply {
	h.t.Helper()
	return h.send(http.MethodPost, path, secret, body)
}

func (h *harness) must(r reply, status int) {
	h.t.Helper()
	if r.status != status {
		h.t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
}

func decodeJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

func randomChallenge(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func challengeOf(t *testing.T, b64 string) []byte {
	t.Helper()
	c, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("challenge %q: %v", b64, err)
	}
	return c
}

// ----- the shapes the page reads -----

type descriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type creationOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Attestation        string       `json:"attestation"`
	ExcludeCredentials []descriptor `json:"excludeCredentials"`
}

type requestOptions struct {
	Challenge        string       `json:"challenge"`
	RPID             string       `json:"rpId"`
	AllowCredentials []descriptor `json:"allowCredentials"`
	UserVerification string       `json:"userVerification"`
}

type beginReply struct {
	Ceremony   string          `json:"ceremony"`
	Technician string          `json:"technician"`
	Options    json.RawMessage `json:"options"`
}

type loginBody struct {
	Ceremony string `json:"ceremony"`
	proto.PasskeyAssertion
}

// ----- technicians -----

// tech is one technician's browser: a passkey and a sign-in cookie.
type tech struct {
	h      *harness
	name   string
	key    *passkeytest.Authenticator
	cookie string // the sign-in cookie's secret
}

func (h *harness) newTech(name string) *tech {
	return &tech{h: h, name: name, key: passkeytest.New(h.t, h.rpID, h.origin)}
}

// mintLink stores a one-time enrollment link for technician, as the admin
// API does, and returns its secret.
func (h *harness) mintLink(technician string) string {
	h.t.Helper()
	secret := model.NewSecret(model.SecretPasskeyLink)
	now := h.clock()
	l := model.PasskeyLink{ID: model.NewID(model.PrefixPasskeyLink), Technician: technician, Hash: model.HashSecret(secret),
		CreatedAt: now, ExpiresAt: now.Add(model.PasskeyLinkTTL)}
	if err := h.st.CreatePasskeyLink(bg, l); err != nil {
		h.t.Fatal(err)
	}
	return secret
}

// enrollBegin opens an enrollment on a link and returns its options.
func (h *harness) enrollBegin(secret string) creationOptions {
	h.t.Helper()
	r := h.post("/api/enroll/begin", "", map[string]string{"token": secret})
	h.must(r, http.StatusOK)
	var b beginReply
	decodeJSON(h.t, r.body, &b)
	var o creationOptions
	decodeJSON(h.t, b.Options, &o)
	return o
}

// registration is the enroll/finish body for tk's passkey over challenge.
func (tk *tech) registration(secret string, challenge []byte, edit ...func(*passkeytest.Ceremony)) map[string]any {
	att := tk.key.Create(challenge, edit...)
	return map[string]any{"token": secret, "credential_id": att.CredentialID, "public_key": att.PublicKey,
		"algorithm": att.Algorithm, "authenticator_data": att.AuthenticatorData, "client_data_json": att.ClientDataJSON,
		"name": tk.name + "'s laptop"}
}

// enroll enrolls tk's passkey through a fresh link, which signs tk in.
func (tk *tech) enroll() *tech {
	h := tk.h
	h.t.Helper()
	secret := h.mintLink(tk.name)
	o := h.enrollBegin(secret)
	r := h.post("/api/enroll/finish", "", tk.registration(secret, challengeOf(h.t, o.Challenge)))
	h.must(r, http.StatusOK)
	c := r.cookie()
	if c == nil || c.Value == "" {
		h.t.Fatal("enrollment set no sign-in cookie")
	}
	tk.cookie = c.Value
	return tk
}

// loginBegin opens a sign-in and returns its ceremony and challenge.
func (h *harness) loginBegin() (string, []byte) {
	h.t.Helper()
	r := h.post("/api/login/begin", "", nil)
	h.must(r, http.StatusOK)
	var b beginReply
	decodeJSON(h.t, r.body, &b)
	var o requestOptions
	decodeJSON(h.t, b.Options, &o)
	return b.Ceremony, challengeOf(h.t, o.Challenge)
}

// signIn signs tk in on another device and returns the reply.
func (tk *tech) signIn() reply {
	h := tk.h
	h.t.Helper()
	id, ch := h.loginBegin()
	return h.post("/api/login/finish", "", loginBody{Ceremony: id, PasskeyAssertion: tk.key.Get(ch)})
}

// approve approves a card ("unlocks" or "changes") on tk's sign-in, as the
// page does: an empty body, no passkey prompt.
func (tk *tech) approve(kind, id string) reply {
	tk.h.t.Helper()
	return tk.h.post("/api/"+kind+"/"+id+"/approve", tk.cookie, nil)
}

// ----- cards -----

func (h *harness) unlock(technician, client string) model.Unlock {
	h.t.Helper()
	now := h.clock()
	u := model.Unlock{ID: model.NewID(model.PrefixUnlock), Technician: technician, Client: client, Session: "idp_s",
		Purpose: "ticket 4411: the print spooler", State: model.UnlockAwaiting, Duration: time.Hour,
		IdleTimeout: model.DefaultUnlockIdle, RequestedAt: now, Deadline: now.Add(model.UnlockApprovalWindow)}
	if err := h.st.CreateUnlock(bg, u); err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) access(technician, unlock string) model.AccessRequest {
	h.t.Helper()
	now := h.clock()
	a := model.AccessRequest{ID: model.NewID(model.PrefixAccess), Client: "acme", Device: h.device.ID, Technician: technician,
		Session: "idp_s", Purpose: "p", State: model.AccessActive, RequestedAt: now, ExpiresAt: now.Add(time.Hour),
		PolicyVersion: 1, Unlock: unlock}
	if err := h.st.CreateAccess(bg, a); err != nil {
		h.t.Fatal(err)
	}
	return a
}

// change submits an apply of a freshly prepared plan under access a.
func (h *harness) change(technician string, a model.AccessRequest) model.ChangeApproval {
	h.t.Helper()
	now := h.clock()
	planID := model.NewID("pln")
	plan := proto.ChangePlan{PlanID: planID, PlanDigest: "digest-" + planID, Op: proto.OpPrepareFileChange, Mode: "replace",
		Reason: "switch the vendor agent to the new mode", Before: proto.FileSnapshot{Path: planPath, Size: 120, SHA256: beforeHash},
		AfterSHA256: afterHash, AfterSize: 124, Diff: diffText, DiffLines: 6, PreparedAt: now, ExpiresAt: now.Add(time.Hour)}
	raw, err := json.Marshal(plan)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.st.CreateChangePlan(bg, model.ChangePlanRecord{PlanID: planID, AccessID: a.ID, Client: a.Client, Device: a.Device,
		Technician: technician, Digest: plan.PlanDigest, Plan: raw, PreparedAt: now, ExpiresAt: plan.ExpiresAt}); err != nil {
		h.t.Fatal(err)
	}
	c := model.ChangeApproval{ID: model.NewID(model.PrefixChange), Op: proto.OpApplyFileChange, Technician: technician,
		Client: a.Client, Device: a.Device, AccessID: a.ID, GrantID: "grt_1", Session: "idp_s", PlanID: planID,
		PlanDigest: plan.PlanDigest, State: model.ChangeAwaiting, RequestedAt: now, ExpiresAt: now.Add(model.ChangeApprovalWindow),
		Nonce: model.NewSecret("nonce"), RequestID: model.NewID("req")}
	if err := h.st.CreateChangeApproval(bg, c); err != nil {
		h.t.Fatal(err)
	}
	return c
}

// ----- the tests that need no technician -----

func TestNewChecksItsConfig(t *testing.T) {
	h := newHarness(t)
	for name, cfg := range map[string]companion.Config{
		"no store":              {Directory: h.st, Gate: h.gate, Origin: origin},
		"no gate":               {Store: h.st, Directory: h.st, Origin: origin},
		"http on a real host":   {Store: h.st, Directory: h.st, Gate: h.gate, Origin: "http://keyhole.test"},
		"a path":                {Store: h.st, Directory: h.st, Gate: h.gate, Origin: origin + "/app"},
		"an RP ID it can't use": {Store: h.st, Directory: h.st, Gate: h.gate, Origin: origin, RPID: "other.test"},
	} {
		if _, err := companion.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := companion.New(companion.Config{Store: h.st, Directory: h.st, Gate: h.gate,
		Origin: "https://companion.keyhole.test/", RPID: "keyhole.test"}); err != nil {
		t.Errorf("a parent RP ID: %v", err)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t)
	for _, r := range []struct {
		name  string
		reply reply
		api   bool
	}{
		{"the app", h.get("/", ""), false},
		{"a deep link", h.get("/u/unl_x", ""), false},
		{"the enroll page", h.get("/enroll", ""), false},
		{"a script", h.get("/static/app.js", ""), false},
		{"a missing page", h.get("/nope", ""), false},
		{"the state, signed out", h.get("/api/state", ""), true},
		{"a sign-in", h.post("/api/login/begin", "", nil), true},
		{"a refused post", h.send(http.MethodPost, "/api/login/begin", "", nil, func(r *http.Request) { r.Header.Del("Origin") }), true},
		{"an unknown API", h.get("/api/nope", ""), true},
	} {
		hd := r.reply.header
		if hd.Get("Content-Security-Policy") != csp || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: CSP %q, nosniff %q, referrer %q", r.name, hd.Get("Content-Security-Policy"),
				hd.Get("X-Content-Type-Options"), hd.Get("Referrer-Policy"))
		}
		if r.api && hd.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", r.name, hd.Get("Cache-Control"))
		}
	}
}

func TestPagesAndAssets(t *testing.T) {
	h := newHarness(t)
	for path, script := range map[string]string{
		"/": "/static/app.js", "/u/unl_abc": "/static/app.js", "/c/chg_abc": "/static/app.js", "/enroll": "/static/enroll.js",
	} {
		r := h.get(path, "")
		if r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), "text/html") || !bytes.Contains(r.body, []byte(script)) {
			t.Errorf("%s: %d %s", path, r.status, r.header.Get("Content-Type"))
		}
	}
	for path, ctype := range map[string]string{
		"/static/app.js": "text/javascript", "/static/enroll.js": "text/javascript", "/static/webauthn.js": "text/javascript",
		"/static/app.css": "text/css",
	} {
		if r := h.get(path, ""); r.status != http.StatusOK || !strings.HasPrefix(r.header.Get("Content-Type"), ctype) {
			t.Errorf("%s: %d %s", path, r.status, r.header.Get("Content-Type"))
		}
	}
	for _, path := range []string{"/static/", "/static/index.html", "/static/nope.js", "/favicon.ico", "/u/", "/enroll/x"} {
		if r := h.get(path, ""); r.status != http.StatusNotFound {
			t.Errorf("%s: %d", path, r.status)
		}
	}

	// The pages carry no inline code and load nothing from elsewhere, which
	// is what lets the policy forbid both.
	handler := regexp.MustCompile(`\son[a-z]+\s*=`)
	for _, path := range []string{"/", "/enroll"} {
		page := string(h.get(path, "").body)
		if n, m := strings.Count(page, "<script"), strings.Count(page, `<script src="/static/`); n != m || n == 0 {
			t.Errorf("%s: %d scripts, %d from /static/", path, n, m)
		}
		for _, bad := range []string{"<style", "style=", "javascript:", "http://", "https://"} {
			if strings.Contains(page, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
		if handler.MatchString(page) {
			t.Errorf("%s has an inline event handler", path)
		}
	}
	// The scripts never parse markup, so nothing a machine sends can run.
	for _, path := range []string{"/static/app.js", "/static/enroll.js", "/static/webauthn.js"} {
		js := string(h.get(path, "").body)
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
			if strings.Contains(js, bad) {
				t.Errorf("%s uses %s", path, bad)
			}
		}
	}
}

func TestPostsNeedTheCompanionsOriginAndJSON(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	c := h.change(alice, h.access(alice, u.ID))
	paths := []string{"/api/enroll/begin", "/api/enroll/finish", "/api/login/begin", "/api/login/finish", "/api/logout"}
	for _, action := range []string{"approve", "deny", "lock"} {
		paths = append(paths, "/api/unlocks/"+u.ID+"/"+action)
	}
	for _, action := range []string{"approve", "deny"} {
		paths = append(paths, "/api/changes/"+c.ID+"/"+action)
	}
	setOrigin := func(o string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("Origin", o) } }
	setType := func(ct string) func(*http.Request) { return func(r *http.Request) { r.Header.Set("Content-Type", ct) } }
	for _, path := range paths {
		for name, tc := range map[string]struct {
			edit   func(*http.Request)
			status int
		}{
			"no Origin":         {func(r *http.Request) { r.Header.Del("Origin") }, http.StatusForbidden},
			"another origin":    {setOrigin("https://evil.test"), http.StatusForbidden},
			"another port":      {setOrigin(origin + ":8443"), http.StatusForbidden},
			"plain http":        {setOrigin("http://keyhole.test"), http.StatusForbidden},
			"an opaque origin":  {setOrigin("null"), http.StatusForbidden},
			"a form body":       {setType("application/x-www-form-urlencoded"), http.StatusUnsupportedMediaType},
			"a multipart body":  {setType("multipart/form-data; boundary=x"), http.StatusUnsupportedMediaType},
			"a text body":       {setType("text/plain"), http.StatusUnsupportedMediaType},
			"no content type":   {func(r *http.Request) { r.Header.Del("Content-Type") }, http.StatusUnsupportedMediaType},
			"a JSON look-alike": {setType("application/json-seq"), http.StatusUnsupportedMediaType},
		} {
			if r := h.send(http.MethodPost, path, a.cookie, nil, tc.edit); r.status != tc.status {
				t.Errorf("%s with %s: %d, want %d", path, name, r.status, tc.status)
			}
		}
	}
	if calls := h.gate.Calls(""); len(calls) != 0 {
		t.Fatalf("a refused request reached the gate: %+v", calls)
	}
	if got, _ := h.st.Unlock(bg, u.ID); got.State != model.UnlockAwaiting || got.Nonce != "" {
		t.Fatalf("a refused approve changed the unlock: %+v", got)
	}
	// From the page itself, with a charset, it goes through.
	r := h.send(http.MethodPost, "/api/unlocks/"+u.ID+"/deny", a.cookie, nil, setType("application/json; charset=utf-8"))
	h.must(r, http.StatusOK)
}

func TestBodiesAreCapped(t *testing.T) {
	h := newHarness(t)
	big := `{"ceremony":"` + strings.Repeat("a", 70<<10) + `"}`
	if r := h.post("/api/login/finish", "", big); r.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 70 KiB body: %d", r.status)
	}
	if r := h.post("/api/login/finish", "", `{"ceremony":"x"} {"again":1}`); r.status != http.StatusBadRequest {
		t.Fatalf("two JSON values: %d", r.status)
	}
}

func TestTheAPINeedsASignIn(t *testing.T) {
	h := newHarness(t)
	a := h.newTech(alice).enroll()
	u := h.unlock(alice, "acme")
	c := h.change(alice, h.access(alice, u.ID))
	refused := func(what, secret string) {
		t.Helper()
		for _, r := range []reply{
			h.get("/api/state", secret),
			h.get("/api/unlocks/"+u.ID+"/receipt", secret),
			h.post("/api/logout", secret, nil),
			h.post("/api/unlocks/"+u.ID+"/approve", secret, nil),
			h.post("/api/unlocks/"+u.ID+"/deny", secret, nil),
			h.post("/api/unlocks/"+u.ID+"/lock", secret, nil),
			h.post("/api/changes/"+c.ID+"/approve", secret, nil),
			h.post("/api/changes/"+c.ID+"/deny", secret, nil),
		} {
			if r.status != http.StatusUnauthorized || r.code() != proto.ErrUnauthorized {
				t.Errorf("%s: %d %s", what, r.status, r.body)
			}
		}
	}
	refused("no cookie", "")
	refused("a garbage cookie", "garbage")
	refused("an unknown sign-in", model.NewSecret(model.SecretCompanion))
	refused("another kind of secret", model.NewSecret(model.SecretSession))
	if len(h.gate.Calls("")) != 0 {
		t.Fatal("an unsigned request reached the gate")
	}
	if got, _ := h.st.Unlock(bg, u.ID); got.State != model.UnlockAwaiting || got.Nonce != "" {
		t.Fatalf("an unsigned approve changed the unlock: %+v", got)
	}
	h.must(h.get("/api/state", a.cookie), http.StatusOK)
	// A sign-in ends after an hour.
	h.advance(model.CompanionSessionTTL)
	refused("an expired sign-in", a.cookie)
}
