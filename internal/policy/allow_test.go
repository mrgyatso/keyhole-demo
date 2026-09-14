package policy

import (
	"strings"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

type allowCase struct {
	goos     string
	rules    []proto.AllowRule
	path     string
	isDir    bool
	wantID   string // "" means no rule matches
	wantRoot string
}

func TestMatchAllow(t *testing.T) {
	def := DefaultAllow()
	win, lin, mac := def["windows"], def["linux"], def["darwin"]
	filtered := []proto.AllowRule{
		{ID: "data-logs", Path: `C:\Data`, Files: []string{"*.log"}},
		{ID: "data-all", Path: `C:\Data`},
	}
	malformed := []proto.AllowRule{
		{ID: "relative", Path: `Windows\Logs`},
		{ID: "dotdot", Path: `C:\Windows\..\Windows\Logs`},
		{ID: "slashes", Path: `C:/Windows/Logs`},
		{ID: "mixed", Path: `C:\Windows/Logs`},
		{ID: "empty", Path: ``},
		{ID: "badglob", Path: `C:\Windows\[Logs`},
	}
	cases := []allowCase{
		{"windows", win, `C:\Windows\Logs\CBS\CBS.log`, false, "win-logs", `C:\Windows\Logs`},
		{"windows", win, `c:\WINDOWS\logs\cbs\cbs.log`, false, "win-logs", `c:\WINDOWS\logs`},
		{"windows", win, `C:\Windows\Logs`, true, "win-logs", `C:\Windows\Logs`},
		{"windows", win, `C:\Windows\Logs\`, true, "win-logs", `C:\Windows\Logs`},
		// segment-wise, never a string prefix (CVE-2025-53110's shape)
		{"windows", win, `C:\Windows\LogsSecret\x.log`, false, "", ""},
		{"windows", win, `C:\Windows\LogsSecret`, true, "", ""},
		{"windows", win, `C:\Windows`, true, "", ""},
		{"windows", win, `D:\Windows\Logs\x.log`, false, "", ""},
		// Files filters apply to files only
		{"windows", win, `C:\Windows\INF\setupapi.dev.log`, false, "win-setupapi", `C:\Windows\INF`},
		{"windows", win, `C:\Windows\INF\SETUPAPI.APP.LOG`, false, "win-setupapi", `C:\Windows\INF`},
		{"windows", win, `C:\Windows\INF\oem1.inf`, false, "", ""},
		{"windows", win, `C:\Windows\INF\sub`, true, "win-setupapi", `C:\Windows\INF`},
		{"windows", win, `C:\Windows\System32\dhcp\DhcpSrvLog-Mon.log`, false, "dhcp-audit", `C:\Windows\System32\dhcp`},
		{"windows", win, `C:\Windows\System32\dhcp\dhcp.mdb`, false, "", ""},
		// glob segments; root is the concrete directory they matched
		{"windows", win, `C:\ProgramData\Veeam\Logs\a.log`, false, "vendor-logs", `C:\ProgramData\Veeam\Logs`},
		{"windows", win, `C:\ProgramData\Veeam\Backup\Svc.VeeamBackup.log`, false, "veeam", `C:\ProgramData\Veeam\Backup`},
		{"windows", win, `C:\ProgramData\Veeam\Backup\Svc.txt`, false, "", ""},
		{"windows", win, `C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log\ERRORLOG`, false,
			"sql-errorlog", `C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log`},
		{"windows", win, `C:\ProgramData\ScreenConnect Client (1234abcd)\x.log`, false,
			"screenconnect", `C:\ProgramData\ScreenConnect Client (1234abcd)`},
		{"windows", win, `C:\ProgramData\ScreenConnect Client (1234abcd)\x.exe`, false, "", ""},
		// first rule in order wins, per file
		{"windows", filtered, `C:\Data\x.log`, false, "data-logs", `C:\Data`},
		{"windows", filtered, `C:\Data\x.txt`, false, "data-all", `C:\Data`},
		{"windows", filtered, `C:\Data\sub`, true, "data-logs", `C:\Data`},
		// a glob matches exactly one segment, "**" included
		{"windows", []proto.AllowRule{{ID: "g", Path: `C:\ProgramData\**\Logs`}}, `C:\ProgramData\A\Logs\x.log`, false, "g", `C:\ProgramData\A\Logs`},
		{"windows", []proto.AllowRule{{ID: "g", Path: `C:\ProgramData\**\Logs`}}, `C:\ProgramData\A\B\Logs\x.log`, false, "", ""},
		// whole-drive and whole-filesystem rules
		{"windows", []proto.AllowRule{{ID: "all", Path: `C:\`}}, `C:\Users\bob\x.log`, false, "all", `C:\`},
		{"windows", []proto.AllowRule{{ID: "all", Path: `C:\`}}, `C:\`, true, "all", `C:\`},
		{"linux", []proto.AllowRule{{ID: "all", Path: "/"}}, `/etc/passwd`, false, "all", `/`},
		{"linux", []proto.AllowRule{{ID: "all", Path: "/"}}, `/`, true, "all", `/`},
		// malformed rules and paths never match
		{"windows", malformed, `C:\Windows\Logs\x.log`, false, "", ""},
		{"windows", win, `C:\Windows\Logs\..\x.log`, false, "", ""},
		{"windows", win, `\\?\C:\Windows\Logs\x.log`, false, "", ""},
		// Unix
		{"linux", lin, `/var/log/syslog`, false, "linux-var-log", `/var/log`},
		{"linux", lin, `/var/log`, true, "linux-var-log", `/var/log`},
		{"linux", lin, `/var/logs/x`, false, "", ""},
		{"linux", lin, `/var/log2`, true, "", ""},
		{"linux", lin, `/etc/nginx/nginx.conf`, false, "linux-etc", `/etc`},
		{"linux", lin, `/VAR/log/x`, false, "", ""},
		{"linux", []proto.AllowRule{{ID: "d", Path: "/data", Files: []string{"*.log"}}}, `/data/X.LOG`, false, "", ""},
		{"darwin", mac, `/private/var/LOG/system.log`, false, "mac-var-log", `/private/var/LOG`},
		{"darwin", mac, `/var/log/system.log`, false, "", ""}, // rules are matched on canonical paths
	}
	for _, c := range cases {
		rule, root, ok := MatchAllow(c.goos, c.rules, c.path, c.isDir)
		if ok != (c.wantID != "") || rule.ID != c.wantID || root != c.wantRoot {
			t.Errorf("MatchAllow(%s, %q, dir=%v) = %q, %q, %v; want %q, %q",
				c.goos, c.path, c.isDir, rule.ID, root, ok, c.wantID, c.wantRoot)
		}
	}
}

// Security invariant 5: the hard-deny list beats every allow rule,
// including a rule for a whole drive or the whole filesystem.
func TestHardDenyBeatsEveryAllowRule(t *testing.T) {
	everything := map[string][]proto.AllowRule{
		"windows": {{ID: "all-c", Path: `C:\`}, {ID: "all-d", Path: `D:\`}, {ID: "all-e", Path: `E:\`}},
		"linux":   {{ID: "all", Path: "/"}},
		"darwin":  {{ID: "all", Path: "/"}},
	}
	for _, c := range denyCases {
		rules := everything[c.goos]
		for _, isDir := range []bool{false, true} {
			if _, _, ok := MatchAllow(c.goos, rules, c.path, isDir); !ok {
				t.Fatalf("fixture: %q is not under the catch-all rule", c.path)
			}
			d := Decide(c.goos, rules, c.path, isDir)
			switch {
			case c.want == "" && (!d.Allowed || d.DenyRule != ""):
				t.Errorf("Decide(%s, %q) = %+v; want allowed", c.goos, c.path, d)
			case c.want != "" && (d.Allowed || d.DenyRule != c.want):
				t.Errorf("Decide(%s, %q) = %+v; want denied by %s", c.goos, c.path, d, c.want)
			}
		}
	}
}

func TestDecideForListings(t *testing.T) {
	rules := []proto.AllowRule{{ID: "veeam", Path: `C:\ProgramData\Veeam\Backup`, Files: []string{"*.log"}}}
	cases := []struct {
		path     string
		isDir    bool
		allowed  bool
		denyRule string
	}{
		{`C:\ProgramData\Veeam\Backup\Svc.log`, false, true, ""},
		{`C:\ProgramData\Veeam\Backup\Svc.txt`, false, false, ""}, // filtered out by Files
		{`C:\ProgramData\Veeam\Backup\Sub`, true, true, ""},       // directories stay listable
		{`C:\ProgramData\Veeam\Backup\.ssh`, true, false, "deny-ssh"},
		{`C:\ProgramData\Veeam\Backup\id_rsa.log`, false, false, "deny-ssh-keys"},
		{`C:\ProgramData\Veeam`, true, false, ""}, // above the rule
	}
	for _, c := range cases {
		d := Decide("windows", rules, c.path, c.isDir)
		if d.Allowed != c.allowed || d.DenyRule != c.denyRule {
			t.Errorf("Decide(%q, dir=%v) = %+v; want allowed=%v deny=%q", c.path, c.isDir, d, c.allowed, c.denyRule)
		}
		if d.Allowed && (d.Rule.ID != "veeam" || d.Root != `C:\ProgramData\Veeam\Backup`) {
			t.Errorf("Decide(%q) = %+v; want rule veeam rooted at the Backup dir", c.path, d)
		}
	}
}

func TestRel(t *testing.T) {
	cases := []struct {
		goos, root, p, rel string
		ok                 bool
	}{
		{"windows", `C:\Windows\Logs`, `C:\Windows\Logs\CBS\CBS.log`, `CBS\CBS.log`, true},
		{"windows", `C:\Windows\Logs`, `c:\windows\LOGS\x.log`, `x.log`, true},
		{"windows", `C:\Windows\Logs`, `C:\Windows\Logs`, `.`, true},
		{"windows", `C:\Windows\Logs`, `C:\Windows\LogsSecret\x`, ``, false},
		{"windows", `C:\Windows\Logs`, `C:\Windows`, ``, false},
		{"windows", `C:\`, `C:\x\y`, `x\y`, true},
		{"windows", `C:\`, `D:\x`, ``, false},
		{"linux", `/var/log`, `/var/log/syslog`, `syslog`, true},
		{"linux", `/var/log`, `/var/logs/x`, ``, false},
		{"linux", `/var/log`, `/VAR/log/x`, ``, false},
		{"linux", `/`, `/etc/passwd`, `etc/passwd`, true},
		{"linux", `/`, `/`, `.`, true},
		{"linux", `/var/log`, `relative`, ``, false},
		{"darwin", `/Library/Logs`, `/library/logs/x.log`, `x.log`, true},
	}
	for _, c := range cases {
		rel, ok := Rel(c.goos, c.root, c.p)
		if ok != c.ok || rel != c.rel {
			t.Errorf("Rel(%s, %q, %q) = %q, %v; want %q, %v", c.goos, c.root, c.p, rel, ok, c.rel, c.ok)
		}
	}
}

func TestSplitRule(t *testing.T) {
	cases := []struct {
		goos, path, literal string
		globs               []string
		ok                  bool
	}{
		{"windows", `C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log`, `C:\Program Files\Microsoft SQL Server`, []string{"MSSQL*", "MSSQL", "Log"}, true},
		{"windows", `C:\ProgramData\*\Logs`, `C:\ProgramData`, []string{"*", "Logs"}, true},
		{"windows", `C:\Windows\Logs`, `C:\Windows\Logs`, nil, true},
		{"windows", `C:\Windows\Logs\`, `C:\Windows\Logs`, nil, true},
		{"windows", `C:\`, `C:\`, nil, true},
		{"linux", `/var/log`, `/var/log`, nil, true},
		{"linux", `/`, `/`, nil, true},
		{"linux", `/*/log`, `/`, []string{"*", "log"}, true},
		{"windows", `Windows\Logs`, ``, nil, false},
		{"windows", `C:/Windows`, ``, nil, false},
		{"windows", `C:\a\..\b`, ``, nil, false},
		{"windows", `C:\[`, ``, nil, false},
	}
	for _, c := range cases {
		lit, globs, ok := SplitRule(c.goos, c.path)
		if ok != c.ok || lit != c.literal || strings.Join(globs, "|") != strings.Join(c.globs, "|") {
			t.Errorf("SplitRule(%s, %q) = %q, %q, %v; want %q, %q, %v", c.goos, c.path, lit, globs, ok, c.literal, c.globs, c.ok)
		}
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		goos, pattern, name string
		want                bool
	}{
		{"windows", "*.log", "CBS.LOG", true},
		{"darwin", "*.log", "system.LOG", true},
		{"linux", "*.log", "syslog.LOG", false},
		{"linux", "syslog*", "syslog.1", true},
		{"windows", "setupapi*.log", "setupapi.dev.log", true},
	}
	for _, c := range cases {
		got, err := MatchName(c.goos, c.pattern, c.name)
		if err != nil || got != c.want {
			t.Errorf("MatchName(%s, %q, %q) = %v, %v; want %v", c.goos, c.pattern, c.name, got, err, c.want)
		}
	}
	if _, err := MatchName("linux", "a[", "a"); err == nil {
		t.Error("MatchName accepted a malformed pattern")
	}
}
