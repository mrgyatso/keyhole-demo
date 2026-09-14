package relay

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloads(t *testing.T) {
	h := newHarness(t)
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(h.dl, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("SHA256SUMS", "abc  keyhole-agent-windows-amd64.exe\n")
	write("keyhole-agent-windows-amd64.exe", "MZ")
	write("v1/keyhole-agent-linux-amd64", "ELF")
	write(".env", "SECRET=1")
	outside := filepath.Join(t.TempDir(), "keyhole.db")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.dl, "escape")); err != nil {
		t.Fatal(err)
	}

	get := func(path string) reply { return h.do(http.MethodGet, h.pub.URL+path, nil, nil) }
	for path, want := range map[string]string{
		"/dl/SHA256SUMS":                      "abc  keyhole-agent-windows-amd64.exe\n",
		"/dl/keyhole-agent-windows-amd64.exe": "MZ",
		"/dl/v1/keyhole-agent-linux-amd64":    "ELF",
	} {
		r := get(path)
		if r.status != http.StatusOK || string(r.body) != want || r.header.Get("X-Content-Type-Options") != "nosniff" || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %q", path, r.status, r.body)
		}
	}
	for _, path := range []string{"/dl/", "/dl/v1", "/dl/v1/", "/dl/.env", "/dl/escape", "/dl/missing", "/dl/../keyhole.db", "/dl/%2e%2e/keyhole.db"} {
		if r := get(path); r.status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, r.status)
		}
	}
	if r := h.do(http.MethodPost, h.pub.URL+"/dl/SHA256SUMS", "x", nil); r.status != http.StatusMethodNotAllowed {
		t.Errorf("POST /dl/: %d", r.status)
	}
}
