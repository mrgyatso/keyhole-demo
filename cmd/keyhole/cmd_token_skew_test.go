package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/mrgyatso/keyhole/internal/model"
)

// oldRelay stands in for a relay without temporary installs: it decodes a
// mint request the way every relay does, ignoring fields it does not know, so
// the ephemeral fields never arrive.
func oldRelay(t *testing.T, target string) *httptest.Server {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tokens") {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("mint body: %v", err)
			}
			delete(body, "ephemeral")
			delete(body, "device_ttl_minutes")
			delete(body, "technician")
			b, _ := json.Marshal(body)
			r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// Against a relay without temporary installs, --ephemeral came back as an
// ordinary reusable enrollment token, printed with managed install commands.
// The CLI must notice, show no secret, and leave the stray token unusable.
func TestTokenMintEphemeralRefusesAnOldRelay(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	relay := oldRelay(t, h.admin.URL)
	if err := saveConfig(h.cfgPath, Config{RelayURL: relay.URL, AdminToken: adminToken}); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := h.run("", false, "token", "mint", "acme", "--ephemeral", "--device-ttl", "5m")
	if code == 0 {
		t.Fatalf("an old relay's managed token was accepted as temporary:\n%s", stdout)
	}
	if strings.Contains(stdout+stderr, "khe_acme_") {
		t.Fatalf("the stray token's secret was shown:\n%s%s", stdout, stderr)
	}
	var toks []model.EnrollToken
	if err := json.Unmarshal([]byte(h.ok("token", "list", "acme", "--json")), &toks); err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0].RevokedAt == nil || toks[0].MaxUses != 1 {
		t.Fatalf("the stray token is still usable: %+v", toks)
	}
}
