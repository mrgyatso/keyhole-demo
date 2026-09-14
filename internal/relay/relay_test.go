package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/natsauth/natsauthtest"
	"github.com/mrgyatso/keyhole/internal/proto"
	"github.com/mrgyatso/keyhole/internal/store"
)

var bg = context.Background()

// syncBuffer collects log output written from many goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// flakyAudit is an audit.MemStore whose appends can be made to fail.
type flakyAudit struct {
	*audit.MemStore
	fail atomic.Bool
}

func (f *flakyAudit) Append(ctx context.Context, e *audit.Entry) error {
	if f.fail.Load() {
		return errors.New("audit store unavailable")
	}
	return f.MemStore.Append(ctx, e)
}

// harness runs a relay against an embedded nats-server started from the
// natsauth-generated config, with both listeners on loopback.
type harness struct {
	t          *testing.T
	nats       *server.Server
	op         *natsauth.Operator
	st         *store.Store
	conns      *ConnManager
	audit      *flakyAudit
	srv        *Server
	pub, priv  *httptest.Server
	adminToken string
	logs       *syncBuffer
	dl         string
}

func newHarness(t *testing.T, configure ...func(*Config)) *harness {
	t.Helper()
	op, err := natsauth.NewOperator("keyhole-test")
	if err != nil {
		t.Fatal(err)
	}
	ns := natsauthtest.StartServer(t, op)
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "keyhole.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	conns := NewConnManager(ns.ClientURL(), st, log)
	t.Cleanup(conns.Close)
	sys, err := op.NewSysUser("relay-sys")
	if err != nil {
		t.Fatal(err)
	}
	dl := filepath.Join(dir, "dl")
	if err := os.Mkdir(dl, 0o755); err != nil {
		t.Fatal(err)
	}
	aud := &flakyAudit{MemStore: audit.NewMemStore()}
	cfg := Config{
		Store: st, Conns: conns, Operator: op, SysCreds: sys, Audit: aud,
		AgentNATSURLs: []string{"wss://keyhole.test/nats"},
		MCPURL:        "http://100.64.0.1:7802/mcp",
		DownloadDir:   dl,
		Logger:        log,
	}
	for _, c := range configure {
		c(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	h := &harness{t: t, nats: ns, op: op, st: st, conns: conns, audit: aud, srv: srv, logs: logs, dl: dl}
	h.adminToken = model.NewSecret(model.SecretAdmin)
	if err := st.SetAdminTokenHash(bg, model.HashSecret(h.adminToken), time.Now()); err != nil {
		t.Fatal(err)
	}
	h.pub = httptest.NewServer(srv.PublicHandler())
	t.Cleanup(h.pub.Close)
	h.priv = httptest.NewServer(srv.PrivateHandler())
	t.Cleanup(h.priv.Close)
	return h
}

type reply struct {
	status int
	body   []byte
	header http.Header
}

func (r reply) errCode() string {
	var e proto.HTTPError
	_ = json.Unmarshal(r.body, &e)
	return e.Error.Code
}

// do sends body (nil, a string, []byte, or a value to marshal as JSON).
func (h *harness) do(method, url string, body any, hdr http.Header) reply {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
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

func (h *harness) adminHeader() http.Header {
	return http.Header{"Authorization": {"Bearer " + h.adminToken}, adminapi.ActorHeader: {"alice"}}
}

// call invokes an admin route with the admin token, as actor "alice".
func (h *harness) call(route string, params []string, body any) reply {
	h.t.Helper()
	method, pattern := adminapi.Split(route)
	return h.do(method, h.priv.URL+adminapi.Fill(pattern, params...), body, h.adminHeader())
}

// must calls an admin route, requires 200, and decodes the body into out.
func (h *harness) must(route string, params []string, body, out any) {
	h.t.Helper()
	r := h.call(route, params, body)
	if r.status != http.StatusOK {
		h.t.Fatalf("%s %v: status %d: %s", route, params, r.status, r.body)
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			h.t.Fatalf("%s: decode: %v", route, err)
		}
	}
}

func (h *harness) createClient(slug string) adminapi.ClientInfo {
	h.t.Helper()
	var info adminapi.ClientInfo
	h.must(adminapi.RouteCreateClient, nil, adminapi.CreateClientRequest{Slug: slug, Name: strings.ToUpper(slug)}, &info)
	return info
}

func (h *harness) mintToken(slug string, req adminapi.MintTokenRequest) adminapi.MintTokenResponse {
	h.t.Helper()
	var out adminapi.MintTokenResponse
	h.must(adminapi.RouteMintToken, []string{slug}, req, &out)
	return out
}

func (h *harness) entries(client string) []audit.Entry {
	h.t.Helper()
	var out []audit.Entry
	if err := h.audit.Range(bg, client, time.Time{}, time.Time{}, func(e audit.Entry) error {
		out = append(out, e)
		return nil
	}); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *harness) device(id string) model.Device {
	h.t.Helper()
	d, err := h.st.Device(bg, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

type deviceKey struct{ pub, seed string }

func newDeviceKey(t *testing.T) deviceKey {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	return deviceKey{pub, string(seed)}
}

func enrollRequest(token string, k deviceKey, machine string) proto.EnrollRequest {
	return proto.EnrollRequest{
		Token: token, PublicKey: k.pub, Hostname: "SRV-" + machine, MachineID: machine,
		OS: "windows", OSVersion: "10.0.26100", Arch: "amd64", AgentVersion: "v0.1.0",
	}
}

func (h *harness) enroll(req any, hdr http.Header) reply {
	h.t.Helper()
	return h.do(http.MethodPost, h.pub.URL+proto.EnrollPath, req, hdr)
}

// enrollDevice enrolls a fresh device key.
func (h *harness) enrollDevice(token, machine string) (proto.EnrollResponse, deviceKey) {
	h.t.Helper()
	k := newDeviceKey(h.t)
	r := h.enroll(enrollRequest(token, k, machine), nil)
	if r.status != http.StatusOK {
		h.t.Fatalf("enroll: %d %s", r.status, r.body)
	}
	var resp proto.EnrollResponse
	if err := json.Unmarshal(r.body, &resp); err != nil {
		h.t.Fatal(err)
	}
	return resp, k
}

// agent is a device's NATS connection.
type agent struct {
	*nats.Conn
	closed chan struct{}
}

func dialAgent(url, userJWT, seed string) (*agent, error) {
	a := &agent{closed: make(chan struct{})}
	nc, err := nats.Connect(url, nats.UserJWTAndSeed(userJWT, seed), nats.NoReconnect(),
		nats.ClosedHandler(func(*nats.Conn) { close(a.closed) }))
	if err != nil {
		return nil, err
	}
	a.Conn = nc
	return a, nil
}

func (h *harness) connectAgent(resp proto.EnrollResponse, k deviceKey) *agent {
	h.t.Helper()
	a, err := dialAgent(h.nats.ClientURL(), resp.UserJWT, k.seed)
	if err != nil {
		h.t.Fatalf("agent connect: %v", err)
	}
	h.t.Cleanup(a.Close)
	return a
}

func (a *agent) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-a.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("device still connected")
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func adminRoutes() []string {
	return []string{
		adminapi.RouteListClients, adminapi.RouteCreateClient, adminapi.RouteGetClient,
		adminapi.RouteDisableClient, adminapi.RouteEnableClient,
		adminapi.RouteGetPolicy, adminapi.RoutePutPolicy,
		adminapi.RouteListTokens, adminapi.RouteMintToken, adminapi.RouteRevokeToken,
		adminapi.RouteListDevices, adminapi.RouteRevokeDevice,
		adminapi.RouteListSessions, adminapi.RouteMintSession, adminapi.RouteRevokeSession,
		adminapi.RouteListTechnicianClients, adminapi.RouteGrantTechnicianClient, adminapi.RouteRevokeTechnicianClient,
		adminapi.RouteAuditExport, adminapi.RouteAuditVerify,
	}
}

func TestNewRequiresConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted an empty config")
	}
}

// TestPublicListenerServesNoPrivateRoutes is security invariant #8.
func TestPublicListenerServesNoPrivateRoutes(t *testing.T) {
	var mcpHits atomic.Int32
	h := newHarness(t, func(c *Config) {
		c.MCP = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mcpHits.Add(1)
			w.WriteHeader(http.StatusOK)
		})
	})
	h.createClient("acme")
	for _, route := range adminRoutes() {
		method, pattern := adminapi.Split(route)
		path := adminapi.Fill(pattern, "acme")
		if r := h.do(method, h.pub.URL+path, nil, h.adminHeader()); r.status != http.StatusNotFound {
			t.Errorf("public %s %s: status %d, want 404", method, path, r.status)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions} {
		for _, p := range []string{"/mcp", "/mcp/", "/MCP", "/v1/admin", "/v1/admin/"} {
			if r := h.do(method, h.pub.URL+p, nil, h.adminHeader()); r.status != http.StatusNotFound {
				t.Errorf("public %s %s: status %d, want 404", method, p, r.status)
			}
		}
	}
	if mcpHits.Load() != 0 {
		t.Fatal("the public listener reached the MCP handler")
	}

	// The same routes do exist on the private listener.
	if r := h.call(adminapi.RouteGetClient, []string{"acme"}, nil); r.status != http.StatusOK {
		t.Fatalf("private get client: %d", r.status)
	}
	if r := h.do(http.MethodPost, h.priv.URL+"/mcp", "{}", nil); r.status != http.StatusOK || mcpHits.Load() != 1 {
		t.Fatalf("private /mcp: %d", r.status)
	}
	for _, base := range []string{h.pub.URL, h.priv.URL} {
		if r := h.do(http.MethodGet, base+"/healthz", nil, nil); r.status != http.StatusOK {
			t.Fatalf("%s/healthz: %d", base, r.status)
		}
	}
}

func TestMCPRoute(t *testing.T) {
	h := newHarness(t)
	if r := h.do(http.MethodPost, h.priv.URL+"/mcp", "{}", nil); r.status != http.StatusServiceUnavailable {
		t.Fatalf("no gateway configured: status %d, want 503", r.status)
	}

	h = newHarness(t, func(c *Config) {
		c.MCP = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, flusher := w.(http.Flusher)
			w.Header().Set("X-Flusher", strconv.FormatBool(flusher))
			w.Header().Set("X-Auth", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusAccepted)
		})
	})
	r := h.do(http.MethodPost, h.priv.URL+"/mcp", "{}", http.Header{"Authorization": {"Bearer khs_session"}})
	if r.status != http.StatusAccepted {
		t.Fatalf("status %d", r.status)
	}
	if r.header.Get("X-Flusher") != "true" {
		t.Fatal("the MCP handler cannot flush (streaming responses would break)")
	}
	if r.header.Get("X-Auth") != "Bearer khs_session" {
		t.Fatal("the session bearer did not reach the MCP handler")
	}
}
