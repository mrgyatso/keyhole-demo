package ninja

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/ninja/ninjafake"
)

const (
	testID     = "cid-123"
	testSecret = "s3cr3t-value-never-printed"
)

func newPair(t *testing.T, allowed ...int) (*ninjafake.Server, *Client) {
	t.Helper()
	f := ninjafake.New(testID, testSecret)
	t.Cleanup(f.Close)
	c, err := New(Credentials{BaseURL: f.URL, ClientID: testID, ClientSecret: testSecret}, allowed, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestTokenFetchedOnceAndCached(t *testing.T) {
	f, c := newPair(t)
	f.AddOrg(1, "A")
	for range 3 {
		if _, err := c.Organization(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.TokenRequests(); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	reqs := f.Requests()
	form := reqs[0].Form
	if form.Get("grant_type") != "client_credentials" || form.Get("client_id") != testID ||
		form.Get("client_secret") != testSecret || form.Get("scope") != "monitoring management" {
		t.Fatalf("token form = %v", form)
	}
	for _, r := range reqs[1:] {
		if r.Auth != "Bearer tok-1" {
			t.Fatalf("%s %s auth = %q", r.Method, r.Path, r.Auth)
		}
	}
}

func TestTokenRefreshedBeforeExpiry(t *testing.T) {
	f, c := newPair(t)
	f.AddOrg(1, "A")
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	get := func() {
		t.Helper()
		if _, err := c.Organization(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	get()
	now = now.Add(58 * time.Minute)
	get()
	if n := f.TokenRequests(); n != 1 {
		t.Fatalf("token requests = %d before expiry, want 1", n)
	}
	now = now.Add(2 * time.Minute) // inside the one-minute refresh margin
	get()
	if n := f.TokenRequests(); n != 2 {
		t.Fatalf("token requests = %d after expiry, want 2", n)
	}
}

func TestRejectedTokenRetriedOnce(t *testing.T) {
	f, c := newPair(t)
	f.AddOrg(1, "A")
	if _, err := c.Organization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	f.RevokeTokens()
	if _, err := c.Organization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if n := f.TokenRequests(); n != 2 {
		t.Fatalf("token requests = %d, want 2", n)
	}
}

func TestOrganizationsPaginates(t *testing.T) {
	f, c := newPair(t)
	for i := 1; i <= 250; i++ {
		f.AddOrg(i*2, fmt.Sprintf("Org %d", i))
	}
	orgs, err := c.Organizations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 250 || orgs[0].ID != 2 || orgs[249].ID != 500 {
		t.Fatalf("got %d orgs, first %v last %v", len(orgs), orgs[0], orgs[len(orgs)-1])
	}
	var afters []string
	for _, r := range f.Requests() {
		if r.Path == "/v2/organizations" {
			if r.Query.Get("pageSize") != "100" {
				t.Fatalf("pageSize = %q", r.Query.Get("pageSize"))
			}
			afters = append(afters, r.Query.Get("after"))
		}
	}
	if strings.Join(afters, ",") != ",200,400" {
		t.Fatalf("after params = %q", afters)
	}
}

func TestUpdateCustomFields(t *testing.T) {
	f, c := newPair(t, 42)
	f.AddOrg(42, "Keyhole Test Org")
	f.SetField(42, "otherField", "keep")
	ctx := context.Background()

	err := c.UpdateOrganizationCustomFields(ctx, 42, map[string]any{FieldEnrollToken: "khe_acme_x", FieldDeploy: true})
	if err != nil {
		t.Fatal(err)
	}
	got := f.Fields(42)
	if got[FieldEnrollToken] != "khe_acme_x" || got[FieldDeploy] != true || got["otherField"] != "keep" {
		t.Fatalf("fields = %v", got)
	}
	reqs := f.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPatch || last.Path != "/v2/organization/42/custom-fields" {
		t.Fatalf("last request = %s %s", last.Method, last.Path)
	}
	if string(last.Body) != `{"keyholeDeploy":true,"keyholeEnrollToken":"khe_acme_x"}` {
		t.Fatalf("body = %s", last.Body)
	}

	raw, err := c.OrganizationCustomFields(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[FieldDeploy]) != "true" || string(raw["otherField"]) != `"keep"` {
		t.Fatalf("read back = %v", raw)
	}
}

func TestWriteRailRefusesOtherOrgs(t *testing.T) {
	f, c := newPair(t, 42)
	f.AddOrg(7, "A real client")
	err := c.UpdateOrganizationCustomFields(context.Background(), 7, map[string]any{FieldDeploy: true})
	var na *NotAllowedError
	if !errors.As(err, &na) || na.OrgID != 7 || len(na.Allowed) != 1 || na.Allowed[0] != 42 {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "not in the allowed organizations (42)") {
		t.Fatalf("message = %q", err)
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("a refused write made %d requests", n)
	}
	if got := f.Fields(7); got != nil {
		t.Fatalf("org 7 fields changed: %v", got)
	}

	empty, err := New(Credentials{BaseURL: f.URL, ClientID: testID, ClientSecret: testSecret}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := empty.UpdateOrganizationCustomFields(context.Background(), 42, map[string]any{FieldDeploy: true}); !errors.As(err, &na) {
		t.Fatalf("empty allowlist: err = %v", err)
	}
}

func TestSecureFieldWriteDenied(t *testing.T) {
	f, c := newPair(t, 42)
	f.AddOrg(42, "T")
	f.DenyField(FieldEnrollToken, "Custom field is not writable through the API")
	err := c.UpdateOrganizationCustomFields(context.Background(), 42, map[string]any{FieldEnrollToken: "khe_acme_secret"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "API permission") || !strings.Contains(msg, "not writable through the API") {
		t.Fatalf("message lacks the permission hint: %q", msg)
	}
	if strings.Contains(msg, "khe_acme_secret") {
		t.Fatal("error echoes the token")
	}
}

func TestBadCredentialsDoNotLeakSecret(t *testing.T) {
	f := ninjafake.New(testID, testSecret)
	defer f.Close()
	c, err := New(Credentials{BaseURL: f.URL, ClientID: testID, ClientSecret: "wrong-secret-value"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Organizations(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "Bad client credentials") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "wrong-secret-value") {
		t.Fatal("error echoes the client secret")
	}
}

func TestNotFoundAndRateLimit(t *testing.T) {
	_, c := newPair(t)
	_, err := c.Organization(context.Background(), 99)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound || apiErr.Message != "Organization not found" {
		t.Fatalf("err = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	rl, err := New(Credentials{BaseURL: srv.URL, ClientID: "a", ClientSecret: "b"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rl.Organizations(context.Background())
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != "30" || !strings.Contains(err.Error(), "retry after 30s") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidatesBaseURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://app.ninjarmm.com":     "https://app.ninjarmm.com",
		"https://eu.ninjarmm.com/":     "https://eu.ninjarmm.com",
		"http://127.0.0.1:8080":        "http://127.0.0.1:8080",
		"http://localhost:1":           "http://localhost:1",
		"http://app.ninjarmm.com":      "",
		"https://app.ninjarmm.com/v2":  "",
		"app.ninjarmm.com":             "",
		"https://u:p@app.ninjarmm.com": "",
		"":                             "",
	} {
		c, err := New(Credentials{BaseURL: raw, ClientID: "a", ClientSecret: "b"}, nil, nil)
		switch {
		case want == "" && err == nil:
			t.Errorf("%q accepted", raw)
		case want != "" && err != nil:
			t.Errorf("%q: %v", raw, err)
		case want != "" && c.base != want:
			t.Errorf("%q -> %q, want %q", raw, c.base, want)
		}
	}
	if _, err := New(Credentials{BaseURL: "https://app.ninjarmm.com"}, nil, nil); err == nil {
		t.Error("missing client ID and secret accepted")
	}
}

func TestLoadCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ninja.env")
	noEnv := func(string) string { return "" }
	content := "# NinjaOne API client app\nexport NINJA_BASE_URL=https://app.ninjarmm.com\nNINJA_CLIENT_ID='abc'\nNINJA_CLIENT_SECRET=\"sec ret\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadCredentials(path, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://app.ninjarmm.com" || c.ClientID != "abc" || c.ClientSecret != "sec ret" {
		t.Fatalf("from file: %v", c)
	}

	c, err = LoadCredentials(path, func(k string) string {
		if k == EnvClientID {
			return "env-id"
		}
		return ""
	})
	if err != nil || c.ClientID != "env-id" || c.ClientSecret != "sec ret" {
		t.Fatalf("env override: %v %v", c, err)
	}

	full := map[string]string{EnvBaseURL: "https://eu.ninjarmm.com", EnvClientID: "i", EnvClientSecret: "s"}
	missing := filepath.Join(dir, "absent.env")
	if c, err = LoadCredentials(missing, func(k string) string { return full[k] }); err != nil || c.BaseURL != "https://eu.ninjarmm.com" {
		t.Fatalf("env only: %v %v", c, err)
	}
	_, err = LoadCredentials(missing, func(k string) string {
		if k == EnvClientSecret {
			return ""
		}
		return full[k]
	})
	if err == nil || !strings.Contains(err.Error(), EnvClientSecret) || strings.Contains(err.Error(), EnvClientID) {
		t.Fatalf("partial env: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadCredentials(path, noEnv); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("0644 file: %v", err)
	}

	bad := filepath.Join(dir, "bad.env")
	if err := os.WriteFile(bad, []byte("garbage-secret-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadCredentials(bad, noEnv)
	if err == nil || !strings.Contains(err.Error(), "line 1") || strings.Contains(err.Error(), "garbage-secret-line") {
		t.Fatalf("malformed line: %v", err)
	}
}

func TestCredentialsFormattingHidesSecret(t *testing.T) {
	c := Credentials{BaseURL: "https://app.ninjarmm.com", ClientID: "cid", ClientSecret: testSecret}
	for _, s := range []string{
		fmt.Sprint(c), fmt.Sprintf("%v|%+v|%#v|%s", c, c, c, c), fmt.Sprintf("%v", &c),
	} {
		if strings.Contains(s, testSecret) {
			t.Fatalf("formatted credentials show the secret: %s", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("ninja", "creds", c)
	if strings.Contains(buf.String(), testSecret) || !strings.Contains(buf.String(), "cid") {
		t.Fatalf("slog output: %s", buf.String())
	}
}
