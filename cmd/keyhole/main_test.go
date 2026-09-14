package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/adminclient/adminfake"
	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/ninja"
	"github.com/mrgyatso/keyhole/internal/ninja/ninjafake"
	"github.com/mrgyatso/keyhole/internal/proto"
)

const adminToken = "kha_abcdefghijklmnopqrstuvwxyz234567"

type harness struct {
	t       *testing.T
	admin   *adminfake.Server
	ninja   *ninjafake.Server
	dir     string
	cfgPath string
	env     map[string]string
	now     time.Time
	editor  func(path string) error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	h.admin = adminfake.New(adminToken)
	t.Cleanup(h.admin.Close)
	h.admin.SetNow(func() time.Time { return h.now })
	h.ninja = ninjafake.New("cid-1", "csecret-1")
	t.Cleanup(h.ninja.Close)
	h.cfgPath = filepath.Join(h.dir, "keyhole", "config.json")
	h.env = map[string]string{"KEYHOLE_CONFIG": h.cfgPath, "USER": "zach", "HOME": h.dir}
	if err := saveConfig(h.cfgPath, Config{
		RelayURL: h.admin.URL, AdminToken: adminToken, Ninja: NinjaConfig{AllowedOrgIDs: []int{42}},
	}); err != nil {
		t.Fatal(err)
	}
	env := "NINJA_BASE_URL=" + h.ninja.URL + "\nNINJA_CLIENT_ID=cid-1\nNINJA_CLIENT_SECRET=csecret-1\n"
	if err := os.WriteFile(ninjaEnvPath(h.cfgPath), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// run executes keyhole with args. interactive says whether stdin counts
// as a terminal.
func (h *harness) run(stdin string, interactive bool, args ...string) (stdout, stderr string, code int) {
	h.t.Helper()
	var out, errb bytes.Buffer
	a := &app{
		in: strings.NewReader(stdin), out: &out, errw: &errb,
		getenv:      func(k string) string { return h.env[k] },
		interactive: interactive,
		now:         func() time.Time { return h.now },
		editFile: func(_ context.Context, path string) error {
			if h.editor == nil {
				h.t.Fatal("editor opened unexpectedly")
			}
			return h.editor(path)
		},
	}
	a.readSecret = func() (string, error) { return readLine(a.in) }
	code = a.run(context.Background(), args)
	return out.String(), errb.String(), code
}

func (h *harness) ok(args ...string) string {
	h.t.Helper()
	out, errOut, code := h.run("", false, args...)
	if code != exitOK {
		h.t.Fatalf("keyhole %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// requests counts admin API requests with the given method and path suffix.
func (h *harness) requests(method, suffix string) int {
	n := 0
	for _, r := range h.admin.Requests() {
		if r.Method == method && strings.HasSuffix(r.Path, suffix) {
			n++
		}
	}
	return n
}

func TestDispatchAndUsage(t *testing.T) {
	h := newHarness(t)
	if _, errOut, code := h.run("", false); code != exitUsage || !strings.Contains(errOut, "keyhole client add") {
		t.Fatalf("no args: exit %d, %q", code, errOut)
	}
	if out := h.ok("help"); !strings.Contains(out, "keyhole ninja push <slug> --org ID") {
		t.Fatalf("help: %q", out)
	}
	if _, errOut, code := h.run("", false, "frobnicate"); code != exitUsage || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("unknown: exit %d, %q", code, errOut)
	}
	if _, errOut, code := h.run("", false, "client"); code != exitUsage || !strings.Contains(errOut, "add, list, show, disable, enable") {
		t.Fatalf("group only: exit %d, %q", code, errOut)
	}
	if _, errOut, code := h.run("", false, "client", "add"); code != exitUsage || !strings.Contains(errOut, "missing <slug>") {
		t.Fatalf("missing arg: exit %d, %q", code, errOut)
	}
	if _, _, code := h.run("", false, "client", "list", "--bogus"); code != exitUsage {
		t.Fatalf("bad flag: exit %d", code)
	}
	if _, _, code := h.run("", false, "client", "list", "-h"); code != exitOK {
		t.Fatalf("-h: exit %d", code)
	}
}

func TestParseArgsInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	name := fs.String("name", "", "")
	asJSON := fs.Bool("json", false, "")
	pos, err := parseArgs(fs, []string{"acme", "--name", "Acme Corp", "extra", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pos, ",") != "acme,extra" || *name != "Acme Corp" || !*asJSON {
		t.Fatalf("pos=%v name=%q json=%v", pos, *name, *asJSON)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	h := newHarness(t)
	fresh := filepath.Join(h.dir, "fresh", "config.json")
	h.env["KEYHOLE_CONFIG"] = fresh
	h.ok("config", "set", "relay_url", "http://relay.example.invalid:7802/")
	fi, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %04o, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(fresh)); di.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode = %04o, want 0700", di.Mode().Perm())
	}
	c, err := loadConfig(fresh)
	if err != nil || c.RelayURL != "http://relay.example.invalid:7802" {
		t.Fatalf("stored relay_url = %q, %v", c.RelayURL, err)
	}

	if err := os.Chmod(fresh, 0o644); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := h.run("", false, "config", "show")
	if code != exitError || !strings.Contains(errOut, "chmod 600") {
		t.Fatalf("world-readable config: exit %d, %q", code, errOut)
	}
}

func TestConfigAdminTokenMasked(t *testing.T) {
	h := newHarness(t)
	secret := "kha_zyxwvutsrqponmlkjihgfedcba765432"
	out, errOut, code := h.run(secret+"\n", false, "config", "set", "admin_token")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out+errOut, secret) {
		t.Fatal("config set echoed the admin token")
	}
	if c, _ := loadConfig(h.cfgPath); c.AdminToken != secret {
		t.Fatalf("stored token = %q", c.AdminToken)
	}
	for _, args := range [][]string{{"config", "show"}, {"config", "show", "--json"}} {
		out := h.ok(args...)
		if strings.Contains(out, secret) || !strings.Contains(out, "kha_…5432") {
			t.Fatalf("%v: %s", args, out)
		}
	}

	_, errOut, _ = h.run("", false, "config", "set", "admin_token", secret)
	if !strings.Contains(errOut, "shell history") {
		t.Fatalf("no shell-history note: %q", errOut)
	}
}

func TestConfigSetValidation(t *testing.T) {
	h := newHarness(t)
	for _, bad := range [][]string{
		{"relay_url", "ftp://x"},
		{"ninja.allowed_org_ids", "abc"},
		{"nope", "x"},
	} {
		if _, _, code := h.run("", false, append([]string{"config", "set"}, bad...)...); code != exitError {
			t.Errorf("config set %v: exit %d", bad, code)
		}
	}
	h.ok("config", "set", "ninja.allowed_org_ids", "42, 7")
	if c, _ := loadConfig(h.cfgPath); len(c.Ninja.AllowedOrgIDs) != 2 || c.Ninja.AllowedOrgIDs[1] != 7 {
		t.Fatalf("allowed = %v", c.Ninja.AllowedOrgIDs)
	}
	h.ok("config", "set", "ninja.allowed_org_ids", "none")
	if c, _ := loadConfig(h.cfgPath); len(c.Ninja.AllowedOrgIDs) != 0 {
		t.Fatalf("cleared allowed = %v", c.Ninja.AllowedOrgIDs)
	}
}

func TestClientCommands(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("client", "add", "acme", "--name", "Acme Corp"); !strings.Contains(out, "Created client acme (Acme Corp)") {
		t.Fatalf("add: %q", out)
	}
	if _, ok := h.admin.Client("acme"); !ok {
		t.Fatal("client not created")
	}
	before := len(h.admin.Requests())
	if _, _, code := h.run("", false, "client", "add", "Acme!", "--name", "x"); code != exitUsage {
		t.Fatalf("bad slug: exit %d", code)
	}
	if len(h.admin.Requests()) != before {
		t.Fatal("a bad slug reached the relay")
	}

	out := h.ok("client", "list")
	want := "SLUG  NAME       STATUS   DEVICES  ONLINE  CREATED\nacme  Acme Corp  enabled  0        0       " + stamp(h.now) + "\n"
	if out != want {
		t.Fatalf("list:\n%s\nwant:\n%s", out, want)
	}
	var list []adminapi.ClientInfo
	if err := json.Unmarshal([]byte(h.ok("client", "list", "--json")), &list); err != nil || len(list) != 1 {
		t.Fatalf("list --json: %v %v", list, err)
	}
	if out := h.ok("client", "show", "acme"); !strings.Contains(out, "0 enrolled, 0 online") {
		t.Fatalf("show: %q", out)
	}
}

func TestDestructiveCommandsConfirm(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	disabled := func() bool { c, _ := h.admin.Client("acme"); return c.Disabled }

	_, errOut, code := h.run("", false, "client", "disable", "acme")
	if code != exitError || !strings.Contains(errOut, "--yes") || disabled() || h.requests("POST", "/disable") != 0 {
		t.Fatalf("non-interactive without --yes: exit %d, %q", code, errOut)
	}
	_, errOut, code = h.run("n\n", true, "client", "disable", "acme")
	if code != exitError || !strings.Contains(errOut, "aborted") || disabled() {
		t.Fatalf("answered no: exit %d, %q", code, errOut)
	}
	_, errOut, code = h.run("y\n", true, "client", "disable", "acme", "--reason", "incident 7")
	if code != exitOK || !disabled() || h.admin.DisableReason("acme") != "incident 7" {
		t.Fatalf("answered yes: exit %d, %q", code, errOut)
	}
	h.ok("client", "enable", "acme")
	h.ok("client", "disable", "acme", "--yes")
	if !disabled() {
		t.Fatal("--yes did not disable")
	}

	now := h.now
	h.admin.AddDevice(model.Device{ID: "dev_x", Client: "acme", Hostname: "srv", LastSeen: &now})
	if _, _, code := h.run("", false, "device", "revoke", "dev_x"); code != exitError {
		t.Fatalf("device revoke without --yes: exit %d", code)
	}
	if d, _ := h.admin.Device("dev_x"); d.RevokedAt != nil {
		t.Fatal("device revoked without confirmation")
	}
	h.ok("device", "revoke", "dev_x", "-y")
	if d, _ := h.admin.Device("dev_x"); d.RevokedAt == nil {
		t.Fatal("device not revoked")
	}
}

func TestRevokeRefusesSecretsAndWrongIDs(t *testing.T) {
	h := newHarness(t)
	secret := "khe_acme_abcdefghijklmnopqrstuvwxyz234567"
	_, errOut, code := h.run("", false, "token", "revoke", secret, "--yes")
	if code != exitUsage || strings.Contains(errOut, secret) || !strings.Contains(errOut, "that is a secret") {
		t.Fatalf("secret as id: exit %d, %q", code, errOut)
	}
	if _, _, code := h.run("", false, "session", "revoke", "tok_abc", "--yes"); code != exitUsage {
		t.Fatalf("wrong prefix: exit %d", code)
	}
	if n := len(h.admin.Requests()); n != 0 {
		t.Fatalf("refused ids sent %d requests", n)
	}
}

func TestDeviceTable(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	at := func(d time.Duration) *time.Time { t := h.now.Add(-d); return &t }
	h.admin.AddDevice(model.Device{ID: "dev_aaa", Client: "acme", Hostname: "DC01", OS: "windows", AgentVersion: "v0.1.0", LastSeen: at(10 * time.Second)})
	h.admin.AddDevice(model.Device{ID: "dev_bbb", Client: "acme", Hostname: "FS01", OS: "windows", AgentVersion: "v0.1.0", LastSeen: at(2 * time.Hour)})
	h.admin.AddDevice(model.Device{ID: "dev_ccc", Client: "acme", Hostname: "web01", OS: "linux", AgentVersion: "v0.0.9", LastSeen: at(72 * time.Hour), RevokedAt: at(24 * time.Hour)})
	h.admin.AddDevice(model.Device{ID: "dev_ddd", Client: "other", Hostname: "elsewhere"})

	want := "" +
		"ID       HOSTNAME  OS       ONLINE   LAST SEEN  AGENT VERSION\n" +
		"dev_aaa  DC01      windows  yes      10s ago    v0.1.0\n" +
		"dev_bbb  FS01      windows  no       2h ago     v0.1.0\n" +
		"dev_ccc  web01     linux    revoked  3d ago     v0.0.9\n"
	if out := h.ok("device", "list", "acme"); out != want {
		t.Fatalf("device list:\n%s\nwant:\n%s", out, want)
	}
}

func TestTokenMint(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	out := h.ok("token", "mint", "acme", "--max-uses", "1", "--ttl-days", "7", "--note", "srv01")
	toks, _ := (func() ([]model.EnrollToken, error) {
		var list []model.EnrollToken
		err := json.Unmarshal([]byte(h.ok("token", "list", "acme", "--json")), &list)
		return list, err
	})()
	if len(toks) != 1 || toks[0].MaxUses != 1 || toks[0].Note != "srv01" || !toks[0].ExpiresAt.Equal(h.now.AddDate(0, 0, 7)) {
		t.Fatalf("minted token: %+v", toks)
	}
	secret := secretIn(out, "khe_acme_")
	if secret == "" {
		t.Fatalf("no secret in output:\n%s", out)
	}
	for _, want := range []string{
		"$env:KEYHOLE_ENROLL_TOKEN = '" + secret + "'",
		"https://keyhole.example.invalid/dl/keyhole-agent-windows-amd64.exe",
		"install --url 'https://keyhole.example.invalid'",
		"Remove-Item Env:\\KEYHOLE_ENROLL_TOKEN",
		"sudo env KEYHOLE_ENROLL_TOKEN='" + secret + "' /tmp/keyhole-agent install --url 'https://keyhole.example.invalid'",
		"'https://keyhole.example.invalid/dl/keyhole-agent-linux-'\"$a\"",
		"'https://keyhole.example.invalid/dl/keyhole-agent-darwin-'\"$a\"",
		"keyhole token revoke " + toks[0].ID,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mint output lacks %q", want)
		}
	}
	if strings.Contains(out, "--token") {
		t.Error("install commands put the token on the command line")
	}
	if list := h.ok("token", "list", "acme"); strings.Contains(list, secret) || !strings.Contains(list, "0 of 1") {
		t.Fatalf("token list: %s", list)
	}
	if _, _, code := h.run("", false, "token", "mint", "acme", "--ttl-days", "0"); code != exitUsage {
		t.Fatalf("--ttl-days 0: exit %d", code)
	}
}

// secretIn returns the first whitespace-delimited word in s with prefix.
func secretIn(s, prefix string) string {
	for _, f := range strings.Fields(s) {
		if strings.HasPrefix(f, prefix) {
			return f
		}
	}
	return ""
}

func TestSessionMint(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	out := h.ok("session", "mint", "acme", "--ttl", "90m", "--note", "T-1")
	var req adminapi.MintSessionRequest
	reqs := h.admin.Requests()
	if err := json.Unmarshal(reqs[len(reqs)-1].Body, &req); err != nil {
		t.Fatal(err)
	}
	if req.Tech != "zach" || req.TTLMinutes != 90 || req.Note != "T-1" {
		t.Fatalf("request = %+v", req)
	}
	if !strings.Contains(out, "claude mcp add --transport http keyhole-acme") || secretIn(out, "khs_") == "" && !strings.Contains(out, "Bearer khs_") {
		t.Fatalf("mint output:\n%s", out)
	}
	if list := h.ok("session", "list", "acme"); strings.Contains(list, "Bearer") || !strings.Contains(list, "active") {
		t.Fatalf("session list: %s", list)
	}
	if _, _, code := h.run("", false, "session", "mint", "acme", "--ttl", "30s"); code != exitUsage {
		t.Fatalf("--ttl 30s: exit %d", code)
	}
}

func TestPolicyEdit(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")

	h.editor = func(string) error { return nil }
	if out := h.ok("policy", "edit", "acme"); !strings.Contains(out, "No changes") {
		t.Fatalf("no-op edit: %q", out)
	}
	if n := h.requests("PUT", "/policy"); n != 0 {
		t.Fatalf("no-op edit sent %d PUTs", n)
	}

	h.editor = func(path string) error {
		b, _ := os.ReadFile(path)
		var p model.ClientPolicy
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		p.Allow["windows"] = append(p.Allow["windows"], ruleFor("custom-app", `C:\ProgramData\CustomApp\Logs`))
		p.Version = 99 // ignored: the relay owns the version
		b, _ = json.Marshal(p)
		return os.WriteFile(path, b, 0o600)
	}
	out := h.ok("policy", "edit", "acme")
	if !strings.Contains(out, "version 2") || !strings.Contains(out, `+ windows custom-app: C:\ProgramData\CustomApp\Logs`) {
		t.Fatalf("edit output: %q", out)
	}
	stored, _ := h.admin.Client("acme")
	if last := stored.Policy.Allow["windows"]; last[len(last)-1].ID != "custom-app" {
		t.Fatalf("stored rules: %v", last)
	}

	h.editor = func(path string) error { return os.WriteFile(path, []byte("{not json"), 0o600) }
	if _, errOut, code := h.run("", false, "policy", "edit", "acme"); code != exitError || !strings.Contains(errOut, "invalid") {
		t.Fatalf("invalid edit: exit %d, %q", code, errOut)
	}
	if n := h.requests("PUT", "/policy"); n != 1 {
		t.Fatalf("PUTs = %d, want only the valid edit's", n)
	}
}

func TestPolicySetStrict(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	file := filepath.Join(h.dir, "p.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"alow":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := h.run("", false, "policy", "set", "acme", "--file", file); code != exitError || !strings.Contains(errOut, `unknown field "alow"`) {
		t.Fatalf("typo: exit %d, %q", code, errOut)
	}
	if n := h.requests("PUT", "/policy"); n != 0 {
		t.Fatal("an invalid policy reached the relay")
	}

	doc := h.ok("policy", "show", "acme", "--json")
	if _, _, code := h.run(doc, false, "policy", "set", "acme", "--file", "-"); code != exitOK {
		t.Fatalf("round trip through stdin: exit %d", code)
	}
}

func ruleFor(id, path string) proto.AllowRule { return proto.AllowRule{ID: id, Path: path} }

func TestValidatePolicy(t *testing.T) {
	p := model.ClientPolicy{
		Allow: map[string][]proto.AllowRule{
			"windows": {ruleFor("a", `Logs`), ruleFor("a", `C:\ok`)},
			"linux":   {ruleFor("", "/var/[log")},
			"plan9":   {ruleFor("p", "/x")},
		},
		MaxReadBytes: 1, MaxFileBytes: 1, MaxListEntries: 1, MaxMatches: 0, SessionBudgetBytes: 1,
	}
	err := validatePolicy(p)
	if err == nil {
		t.Fatal("invalid policy accepted")
	}
	for _, want := range []string{
		`not an absolute Windows path`, `id "a" is already used`, `id is empty`, `not a valid glob`,
		`unknown OS "plan9"`, `max_matches must be greater than zero`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestAuditReport(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	h.admin.SetExport("acme", "csv", []byte("n,time\n1,2026-09-02T00:00:00Z\n"))
	out := filepath.Join(h.dir, "acme.csv")
	h.ok("audit", "report", "acme", "--from", "2026-09-01", "--to", "2026-09-08", "-o", out)
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "n,time\n1,2026-09-02T00:00:00Z\n" {
		t.Fatalf("report = %q, %v", b, err)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %04o", fi.Mode().Perm())
	}
	reqs := h.admin.Requests()
	q := reqs[len(reqs)-1].Query
	wantFrom := time.Date(2026, 9, 1, 0, 0, 0, 0, time.Local).UTC().Format(time.RFC3339)
	if q.Get("from") != wantFrom || q.Get("format") != "csv" {
		t.Fatalf("query = %v, want from %s", q, wantFrom)
	}

	if _, _, code := h.run("", false, "audit", "report", "acme", "--format", "pdf"); code != exitUsage {
		t.Fatalf("pdf without -o: exit %d", code)
	}
	h.admin.Fail(adminapi.RouteAuditExport, http.StatusInternalServerError, "internal", "boom")
	failed := filepath.Join(h.dir, "failed.csv")
	if _, _, code := h.run("", false, "audit", "report", "acme", "-o", failed); code != exitError {
		t.Fatalf("failed export: exit %d", code)
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("a failed export left a file behind")
	}
	entries, _ := os.ReadDir(h.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".keyhole-audit-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     {},
		"2026-09-01T10:00:00Z": time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		"2026-09-01":           time.Date(2026, 9, 1, 0, 0, 0, 0, time.Local),
		"7d":                   now.AddDate(0, 0, -7),
		"36h":                  now.Add(-36 * time.Hour),
	} {
		got, err := parseWhen(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseWhen(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseWhen("yesterday", now); err == nil {
		t.Error("parseWhen accepted nonsense")
	}
}

func TestAuditVerify(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	h.admin.SetVerify("acme", audit.VerifyResult{Client: "acme", Entries: 12, OK: true, Head: strings.Repeat("ab", 32)})
	if out := h.ok("audit", "verify", "acme"); !strings.Contains(out, "intact: 12 entries") {
		t.Fatalf("ok chain: %q", out)
	}
	h.admin.SetVerify("acme", audit.VerifyResult{Client: "acme", Entries: 6, BadAt: 7, Reason: "hash mismatch: entry was altered"})
	out, _, code := h.run("", false, "audit", "verify", "acme")
	if code != exitChainBroken || !strings.Contains(out, "BROKEN at entry 7: hash mismatch") {
		t.Fatalf("broken chain: exit %d, %q", code, out)
	}
	if _, _, code := h.run("", false, "audit", "verify", "acme", "--json"); code != exitChainBroken {
		t.Fatalf("broken chain --json: exit %d", code)
	}
}

func TestNinjaPush(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	h.ninja.AddOrg(42, "Keyhole Test Org")
	out := h.ok("ninja", "push", "acme", "--org", "42", "--enable")

	fields := h.ninja.Fields(42)
	secret, _ := fields[ninja.FieldEnrollToken].(string)
	if !strings.HasPrefix(secret, "khe_acme_") || fields[ninja.FieldDeploy] != true {
		t.Fatalf("ninja fields = %v", fields)
	}
	if strings.Contains(out, secret) {
		t.Fatal("ninja push printed the secret")
	}
	var toks []model.EnrollToken
	_ = json.Unmarshal([]byte(h.ok("token", "list", "acme", "--json")), &toks)
	if len(toks) != 1 || toks[0].Note != "ninja org 42" || toks[0].Hash != "" {
		t.Fatalf("tokens = %+v", toks)
	}
	if tok, _ := h.admin.EnrollToken(toks[0].ID); tok.Hash != model.HashSecret(secret) {
		t.Fatal("the secret in NinjaOne is not the minted token")
	}
	if !strings.Contains(out, "Keyhole Test Org") || !strings.Contains(out, "ticked") {
		t.Fatalf("push output: %q", out)
	}

	out = h.ok("ninja", "push", "acme", "--org", "42")
	if !strings.Contains(out, "not ticked") || !strings.Contains(out, toks[0].ID) {
		t.Fatalf("second push should list the older token and ask for the tick: %q", out)
	}
}

func TestNinjaPushRailRefusesOtherOrgs(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	h.ninja.AddOrg(7, "A real client")
	_, errOut, code := h.run("", false, "ninja", "push", "acme", "--org", "7", "--enable")
	if code != exitError {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"not in the allowed organizations (42)", "keyhole config set ninja.allowed_org_ids 42,7"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	if n := len(h.admin.Requests()); n != 0 {
		t.Fatalf("the relay saw %d requests; nothing should be minted", n)
	}
	if n := len(h.ninja.Requests()); n != 0 {
		t.Fatalf("NinjaOne saw %d requests", n)
	}
}

func TestNinjaPushRevokesTokenWhenWriteFails(t *testing.T) {
	h := newHarness(t)
	h.admin.AddClient("acme", "Acme")
	h.ninja.AddOrg(42, "T")
	h.ninja.DenyField(ninja.FieldEnrollToken, "Field is not writable through the API")
	_, errOut, code := h.run("", false, "ninja", "push", "acme", "--org", "42")
	if code != exitError || !strings.Contains(errOut, "has been revoked") || !strings.Contains(errOut, "API permission") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var toks []model.EnrollToken
	_ = json.Unmarshal([]byte(h.ok("token", "list", "acme", "--json")), &toks)
	if len(toks) != 1 || toks[0].RevokedAt == nil {
		t.Fatalf("the unpushed token is still live: %+v", toks)
	}
}

func TestNinjaFieldsMasked(t *testing.T) {
	h := newHarness(t)
	h.ninja.AddOrg(42, "T")
	tok := "khe_acme_abcdefghijklmnopqrstuvwxyz234567"
	h.ninja.SetField(42, ninja.FieldEnrollToken, tok)
	h.ninja.SetField(42, ninja.FieldDeploy, true)
	h.ninja.SetField(42, "huntressAccountKey", "deadbeefdeadbeef")
	for _, args := range [][]string{{"ninja", "fields", "42"}, {"ninja", "fields", "42", "--json"}} {
		out := h.ok(args...)
		if strings.Contains(out, tok) || strings.Contains(out, "deadbeef") {
			t.Fatalf("%v printed a secret:\n%s", args, out)
		}
		if !strings.Contains(out, "set (khe_…4567)") || !strings.Contains(out, "text, 16 chars") || !strings.Contains(out, "true") {
			t.Fatalf("%v:\n%s", args, out)
		}
	}
	if out := h.ok("ninja", "orgs"); !strings.Contains(out, "42") || !strings.Contains(out, "allowed") {
		t.Fatalf("orgs: %s", out)
	}
}

func TestHints(t *testing.T) {
	h := newHarness(t)
	c, _ := loadConfig(h.cfgPath)
	c.AdminToken = "kha_wrongwrongwrongwrongwrongwrong"
	if err := saveConfig(h.cfgPath, c); err != nil {
		t.Fatal(err)
	}
	if _, errOut, _ := h.run("", false, "client", "list"); !strings.Contains(errOut, "rejected the admin token") {
		t.Fatalf("unauthorized hint: %q", errOut)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	c.RelayURL = "http://" + addr
	if err := saveConfig(h.cfgPath, c); err != nil {
		t.Fatal(err)
	}
	if _, errOut, _ := h.run("", false, "client", "list"); !strings.Contains(errOut, "Is Tailscale up") {
		t.Fatalf("unreachable hint: %q", errOut)
	}

	c.RelayURL = ""
	if err := saveConfig(h.cfgPath, c); err != nil {
		t.Fatal(err)
	}
	if _, errOut, _ := h.run("", false, "client", "list"); !strings.Contains(errOut, "keyhole config set relay_url") {
		t.Fatalf("unset relay hint: %q", errOut)
	}
}
