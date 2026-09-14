package adminclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient"
	"github.com/mrgyatso/keyhole/internal/adminclient/adminfake"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const token = "kha_testtoken"

func newClient(t *testing.T) (*adminfake.Server, *adminclient.Client) {
	t.Helper()
	f := adminfake.New(token)
	t.Cleanup(f.Close)
	return f, adminclient.New(f.URL, token, "zach", nil)
}

// route renders a contract route as "METHOD /path" with its params filled.
func route(r string, vals ...string) string {
	m, p := adminapi.Split(r)
	return m + " " + adminapi.Fill(p, vals...)
}

// result lets a (value, error) call be checked inline: try(f()).must(t).
type result[T any] struct {
	v   T
	err error
}

func try[T any](v T, err error) result[T] { return result[T]{v, err} }

func (r result[T]) must(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.v
}

func TestEveryRoute(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()

	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	ci := try(c.CreateClient(ctx, adminapi.CreateClientRequest{Slug: "acme", Name: "Acme Corp"})).must(t)
	if ci.Slug != "acme" || ci.Name != "Acme Corp" || ci.Disabled {
		t.Fatalf("create: %+v", ci)
	}
	if list := try(c.ListClients(ctx)).must(t); len(list) != 1 || list[0].Slug != "acme" {
		t.Fatalf("list: %+v", list)
	}
	if got := try(c.GetClient(ctx, "acme")).must(t); got.Name != "Acme Corp" {
		t.Fatalf("get: %+v", got)
	}
	if dis := try(c.DisableClient(ctx, "acme", "incident 42")).must(t); !dis.Disabled {
		t.Fatalf("disable: %+v", dis)
	}
	if r := f.DisableReason("acme"); r != "incident 42" {
		t.Fatalf("reason = %q", r)
	}
	if en := try(c.EnableClient(ctx, "acme")).must(t); en.Disabled {
		t.Fatalf("enable: %+v", en)
	}

	pol := try(c.GetPolicy(ctx, "acme")).must(t)
	if pol.Version != 1 || len(pol.Allow["windows"]) == 0 {
		t.Fatalf("policy: %+v", pol)
	}
	pol.MaxMatches = 10
	put := try(c.PutPolicy(ctx, "acme", pol)).must(t)
	if put.Version != 2 || put.MaxMatches != 10 {
		t.Fatalf("put policy: version %d, max matches %d", put.Version, put.MaxMatches)
	}

	mint := try(c.MintToken(ctx, "acme", adminapi.MintTokenRequest{TTLDays: 7, MaxUses: 3, Note: "n"})).must(t)
	if !strings.HasPrefix(mint.Secret, "khe_acme_") || mint.Token.MaxUses != 3 || mint.Token.Note != "n" {
		t.Fatalf("mint token: %+v", mint.Token)
	}
	if toks := try(c.ListTokens(ctx, "acme")).must(t); len(toks) != 1 {
		t.Fatalf("tokens: %+v", toks)
	}
	if err := c.RevokeToken(ctx, mint.Token.ID); err != nil {
		t.Fatal(err)
	}
	if tok, _ := f.EnrollToken(mint.Token.ID); tok.RevokedAt == nil {
		t.Fatal("token not revoked")
	}

	now := time.Now().UTC()
	f.AddDevice(model.Device{ID: "dev_1", Client: "acme", Hostname: "srv01", OS: "windows", LastSeen: &now})
	if devs := try(c.ListDevices(ctx, "acme")).must(t); len(devs) != 1 || devs[0].Hostname != "srv01" {
		t.Fatalf("devices: %+v", devs)
	}
	if err := c.RevokeDevice(ctx, "dev_1"); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.Device("dev_1"); d.RevokedAt == nil {
		t.Fatal("device not revoked")
	}

	ses := try(c.MintSession(ctx, "acme", adminapi.MintSessionRequest{Tech: "zach", TTLMinutes: 60})).must(t)
	if !strings.HasPrefix(ses.Bearer, "khs_") || !strings.Contains(ses.ClaudeAddCommand, ses.Bearer) || ses.MCPURL == "" {
		t.Fatalf("mint session: %+v", ses)
	}
	if sess := try(c.ListSessions(ctx, "acme")).must(t); len(sess) != 1 || sess[0].Tech != "zach" {
		t.Fatalf("sessions: %+v", sess)
	}
	if err := c.RevokeSession(ctx, ses.Session.ID); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.Session(ses.Session.ID); s.RevokedAt == nil {
		t.Fatal("session not revoked")
	}

	f.SetVerify("acme", audit.VerifyResult{Client: "acme", Entries: 5, OK: true, Head: "abc"})
	if vr := try(c.AuditVerify(ctx, "acme")).must(t); vr.Entries != 5 || !vr.OK || vr.Head != "abc" {
		t.Fatalf("verify: %+v", vr)
	}
	f.SetExport("acme", adminclient.FormatJSONL, []byte("{\"n\":1}\n"))
	var buf bytes.Buffer
	n := try(c.AuditExport(ctx, "acme", adminclient.AuditQuery{Format: adminclient.FormatJSONL}, &buf)).must(t)
	if n != 8 || buf.String() != "{\"n\":1}\n" {
		t.Fatalf("export: %d %q", n, buf.String())
	}

	want := []string{
		route(adminapi.RouteHealth),
		route(adminapi.RouteCreateClient),
		route(adminapi.RouteListClients),
		route(adminapi.RouteGetClient, "acme"),
		route(adminapi.RouteDisableClient, "acme"),
		route(adminapi.RouteEnableClient, "acme"),
		route(adminapi.RouteGetPolicy, "acme"),
		route(adminapi.RoutePutPolicy, "acme"),
		route(adminapi.RouteMintToken, "acme"),
		route(adminapi.RouteListTokens, "acme"),
		route(adminapi.RouteRevokeToken, mint.Token.ID),
		route(adminapi.RouteListDevices, "acme"),
		route(adminapi.RouteRevokeDevice, "dev_1"),
		route(adminapi.RouteMintSession, "acme"),
		route(adminapi.RouteListSessions, "acme"),
		route(adminapi.RouteRevokeSession, ses.Session.ID),
		route(adminapi.RouteAuditVerify, "acme"),
		route(adminapi.RouteAuditExport, "acme"),
	}
	reqs := f.Requests()
	if len(reqs) != len(want) {
		t.Fatalf("got %d requests, want %d", len(reqs), len(want))
	}
	for i, r := range reqs {
		if got := r.Method + " " + r.Path; got != want[i] {
			t.Errorf("request %d = %s, want %s", i, got, want[i])
		}
		if r.Path == "/healthz" {
			if r.Auth != "" || r.Actor != "" {
				t.Errorf("health sent credentials: auth=%q actor=%q", r.Auth, r.Actor)
			}
			continue
		}
		if r.Auth != "Bearer "+token || r.Actor != "zach" {
			t.Errorf("%s: auth=%q actor=%q", want[i], r.Auth, r.Actor)
		}
	}
	var dreq adminapi.DisableRequest
	if err := json.Unmarshal(reqs[4].Body, &dreq); err != nil || dreq.Reason != "incident 42" {
		t.Errorf("disable body %s: %v", reqs[4].Body, err)
	}
}

func TestActorOmittedWhenEmpty(t *testing.T) {
	f := adminfake.New(token)
	defer f.Close()
	if _, err := adminclient.New(f.URL, token, "", nil).ListClients(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := f.Requests()[0]; r.Actor != "" {
		t.Fatalf("actor header = %q, want none", r.Actor)
	}
}

func TestErrors(t *testing.T) {
	f, c := newClient(t)
	ctx := context.Background()

	_, err := adminclient.New(f.URL, "kha_wrong", "zach", nil).ListClients(ctx)
	var e *adminclient.Error
	if !errors.As(err, &e) || e.Status != http.StatusUnauthorized || e.Code != proto.ErrUnauthorized {
		t.Fatalf("wrong token: %#v", err)
	}
	if adminclient.ErrorCode(err) != proto.ErrUnauthorized {
		t.Fatalf("ErrorCode = %q", adminclient.ErrorCode(err))
	}

	_, err = c.GetClient(ctx, "nope")
	if !errors.As(err, &e) || e.Status != http.StatusNotFound || e.Code != "not_found" {
		t.Fatalf("unknown client: %#v", err)
	}

	f.AddClient("acme", "Acme")
	f.Fail(adminapi.RouteMintToken, http.StatusConflict, "conflict", "boom")
	_, err = c.MintToken(ctx, "acme", adminapi.MintTokenRequest{})
	if !errors.As(err, &e) || e.Code != "conflict" || e.Message != "boom" || err.Error() != "conflict: boom" {
		t.Fatalf("injected: %#v", err)
	}

	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer raw.Close()
	_, err = adminclient.New(raw.URL, token, "", nil).ListClients(ctx)
	if !errors.As(err, &e) || e.Code != "" || e.Message != "upstream down" || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("plain-text error: %#v", err)
	}
	if adminclient.ErrorCode(errors.New("x")) != "" {
		t.Fatal("ErrorCode of a non-API error")
	}
}

func TestAuditExportStreams(t *testing.T) {
	f, c := newClient(t)
	f.AddClient("acme", "Acme")
	body := bytes.Repeat([]byte("1,2026-09-01T00:00:00Z,tool,acme\n"), 120000) // ~4 MB
	f.SetExport("acme", adminclient.FormatCSV, body)

	edt := time.FixedZone("EDT", -4*3600)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, edt)
	to := from.AddDate(0, 0, 7)
	var buf bytes.Buffer
	n, err := c.AuditExport(context.Background(), "acme", adminclient.AuditQuery{From: from, To: to, Format: adminclient.FormatCSV}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(body)) || !bytes.Equal(buf.Bytes(), body) {
		t.Fatalf("streamed %d bytes, want %d", n, len(body))
	}
	reqs := f.Requests()
	q := reqs[len(reqs)-1].Query
	if q.Get("from") != "2026-09-01T04:00:00Z" || q.Get("to") != "2026-09-08T04:00:00Z" || q.Get("format") != "csv" {
		t.Fatalf("query = %v", q)
	}
}

func TestAuditExportTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
	}))
	defer srv.Close()
	_, err := adminclient.New(srv.URL, token, "", nil).AuditExport(context.Background(), "acme", adminclient.AuditQuery{}, io.Discard)
	if err == nil {
		t.Fatal("a cut-short export returned no error")
	}
}

func TestPathEscaping(t *testing.T) {
	paths := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		paths <- r.URL.EscapedPath()
	}))
	defer srv.Close()
	c := adminclient.New(srv.URL+"/", token, "", nil)
	if err := c.RevokeToken(context.Background(), "a/b?c"); err != nil {
		t.Fatal(err)
	}
	if got := <-paths; got != "/v1/admin/tokens/a%2Fb%3Fc/revoke" {
		t.Fatalf("path = %q", got)
	}
	if err := c.RevokeToken(context.Background(), ""); err == nil {
		t.Fatal("empty id accepted")
	}
	select {
	case p := <-paths:
		t.Fatalf("empty id sent a request to %s", p)
	default:
	}
}

func TestPutPolicyWithoutBody(t *testing.T) {
	stored := policy.DefaultClientPolicy()
	stored.Version = 7
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer srv.Close()
	got, err := adminclient.New(srv.URL, token, "", nil).PutPolicy(context.Background(), "acme", policy.DefaultClientPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 {
		t.Fatalf("version = %d, want the stored policy's 7", got.Version)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	hit := make(chan string, 1)
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hit <- r.Header.Get("Authorization")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	_, err := adminclient.New(srv.URL, token, "", nil).ListClients(context.Background())
	var e *adminclient.Error
	if !errors.As(err, &e) || e.Status != http.StatusFound {
		t.Fatalf("err = %#v, want a 302 *Error", err)
	}
	select {
	case <-hit:
		t.Fatal("the client followed the redirect and replayed the admin token")
	default:
	}
}
