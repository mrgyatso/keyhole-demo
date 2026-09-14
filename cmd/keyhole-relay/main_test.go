package main

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

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
	"github.com/mrgyatso/keyhole/internal/natsauth/natsauthtest"
	"github.com/mrgyatso/keyhole/internal/store"
)

func testConfig(dir string) diskConfig {
	return diskConfig{
		PublicURL:         "https://keyhole.test",
		NATSWSURL:         "wss://keyhole.test/nats",
		MCPURL:            "http://100.64.0.1:7802/mcp",
		NATSDir:           filepath.Join(dir, "nats"),
		NATSClientListen:  natsauth.DefaultClientListen,
		NATSWSListen:      natsauth.DefaultWSListen,
		NATSMonitorListen: natsauth.DefaultMonitorListen,
		NATSURL:           defaultNATSURL,
		PublicListen:      defaultPublic,
		PrivateListen:     defaultPrivate,
	}
}

func TestInitializeStoresOnlyHashedAPISecretAndSecuresFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	p := dataPaths(dir)
	token, created, err := initialize(p, testConfig(dir), false)
	if err != nil {
		t.Fatal(err)
	}
	if !created || !strings.HasPrefix(token, model.SecretAdmin+"_") {
		t.Fatalf("admin token = %q, created = %v", token, created)
	}

	for _, path := range []string{p.config, p.database, p.operator, p.sysCreds,
		filepath.Join(testConfig(dir).NATSDir, natsauth.ConfFile),
		filepath.Join(testConfig(dir).NATSDir, natsauth.OperatorJWTFile)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", path, info.Mode().Perm())
		}
	}

	st, err := os.ReadFile(p.database)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(p.config)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := os.ReadFile(p.operator)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(st, []byte(token)) || bytes.Contains(config, []byte(token)) || bytes.Contains(operator, []byte(token)) {
		t.Fatal("plaintext admin token was written to disk")
	}

	db, err := store.Open(p.database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := db.AdminTokenHash(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hash != model.HashSecret(token) || hash == token {
		t.Fatalf("stored admin token = %q", hash)
	}
}

func TestInitializeForcePreservesDeploymentIdentityAndAdminToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	p := dataPaths(dir)
	cfg := testConfig(dir)
	token, created, err := initialize(p, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first initialization did not create an admin token")
	}
	beforeOperator := mustRead(t, p.operator)
	beforeSys := mustRead(t, p.sysCreds)

	cfg.MCPURL = "http://100.64.0.2:7802/mcp"
	gotToken, gotCreated, err := initialize(p, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if gotCreated || gotToken != "" {
		t.Fatalf("force returned a new token %q, created = %v", gotToken, gotCreated)
	}
	if !bytes.Equal(beforeOperator, mustRead(t, p.operator)) {
		t.Fatal("--force rotated the operator")
	}
	if !bytes.Equal(beforeSys, mustRead(t, p.sysCreds)) {
		t.Fatal("--force rotated the SYS credential")
	}
	db, err := store.Open(p.database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := db.AdminTokenHash(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hash != model.HashSecret(token) {
		t.Fatal("--force rotated the admin token")
	}
	loaded, err := loadDiskConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MCPURL != cfg.MCPURL {
		t.Fatalf("mcp_url = %q", loaded.MCPURL)
	}
}

func TestInitRejectsInvalidURLsBeforeWriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	args := []string{"--data", dir, "--public-url", "https://user:pass@example.test", "--nats-ws-url", "wss://example.test/nats", "--mcp-url", "http://127.0.0.1/mcp"}
	if err := runInit(args, io.Discard, io.Discard); err == nil {
		t.Fatal("init accepted a URL containing credentials")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("data directory was created after validation failure: %v", err)
	}
}

func TestRuntimeWiresDurableAuditGatewayAndSeparateMuxes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "relay")
	p := dataPaths(dir)
	cfg := testConfig(dir)
	adminToken, _, err := initialize(p, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	op, err := natsauth.LoadOperator(p.operator)
	if err != nil {
		t.Fatal(err)
	}
	ns := natsauthtest.StartServer(t, op)
	cfg.NATSURL = ns.ClientURL()
	rt, err := newRuntime(p, cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := rt.relay.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pub := httptest.NewServer(rt.public)
	defer pub.Close()
	priv := httptest.NewServer(rt.private)
	defer priv.Close()

	for _, path := range []string{"/mcp", "/v1/admin/clients"} {
		resp := request(t, http.MethodGet, pub.URL+path, "", "")
		if resp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("public %s status = %d, body = %s", path, resp.StatusCode, body)
		}
		resp.Body.Close()
	}
	resp := request(t, http.MethodGet, priv.URL+"/mcp", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("private MCP status = %d, body = %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	body, _ := json.Marshal(adminapi.CreateClientRequest{Slug: "acme", Name: "ACME"})
	resp = request(t, http.MethodPost, priv.URL+"/v1/admin/clients", string(body), adminToken)
	if resp.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create client status = %d, body = %s", resp.StatusCode, got)
	}
	resp.Body.Close()

	resp = request(t, http.MethodGet, priv.URL+"/v1/admin/clients/acme/audit?format=csv", "", adminToken)
	csv, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(csv, []byte("client.create")) {
		t.Fatalf("CSV audit status = %d, body = %s", resp.StatusCode, csv)
	}
	resp = request(t, http.MethodGet, priv.URL+"/v1/admin/clients/acme/audit?format=pdf", "", adminToken)
	pdf, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.HasPrefix(pdf, []byte("%PDF")) {
		t.Fatalf("PDF audit status = %d, prefix = %q", resp.StatusCode, pdf[:min(len(pdf), 16)])
	}
	resp = request(t, http.MethodGet, priv.URL+"/v1/admin/clients/acme/audit/verify", "", adminToken)
	verify, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(verify, []byte(`"ok":true`)) {
		t.Fatalf("verify status = %d, body = %s", resp.StatusCode, verify)
	}
}

func TestLoadDiskConfigRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode test")
	}
	path := filepath.Join(t.TempDir(), configFile)
	if err := os.WriteFile(path, []byte(`{"nats_ws_url":"wss://example.test/nats","mcp_url":"http://127.0.0.1/mcp"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDiskConfig(path); err == nil || !strings.Contains(err.Error(), "other users") {
		t.Fatalf("load error = %v", err)
	}
}

func request(t *testing.T, method, url, body, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(adminapi.ActorHeader, "relay-command-test")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
