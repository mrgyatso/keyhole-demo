package policy

import (
	"reflect"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestNarrow(t *testing.T) {
	data := proto.AllowRule{ID: "data", Path: `C:\Data`, Files: []string{"*.log"}}
	vendor := proto.AllowRule{ID: "vendor-logs", Path: `C:\ProgramData\*\Logs`, Files: []string{"*.log"}}
	rule := func(id, path string, files ...string) proto.AllowRule {
		r := proto.AllowRule{ID: id, Path: path}
		if len(files) > 0 {
			r.Files = files
		}
		return r
	}
	rules := func(r ...proto.AllowRule) []proto.AllowRule { return r }
	cases := []struct {
		name  string
		goos  string
		rules []proto.AllowRule
		roots []string
		want  []proto.AllowRule
	}{
		{"a rule inside a root is kept whole", "windows",
			rules(rule("veeam", `C:\ProgramData\Veeam\Backup`, "*.log")), []string{`C:\ProgramData`},
			rules(rule("veeam", `C:\ProgramData\Veeam\Backup`, "*.log"))},
		{"a root inside a rule takes the rule's ID and Files", "windows",
			rules(data), []string{`C:\Data\App`}, rules(rule("data", `C:\Data\App`, "*.log"))},
		{"a root equal to a rule keeps the rule", "windows", rules(data), []string{`C:\Data`}, rules(data)},
		{"disjoint", "windows", rules(data), []string{`C:\Other`}, nil},
		{"another drive", "windows", rules(data), []string{`D:\Data`}, nil},
		{"segment-wise, never a string prefix", "windows",
			rules(rule("logs", `C:\Windows\Logs`)), []string{`C:\Windows\LogsSecret`}, nil},
		{"segment-wise, the other way round", "windows",
			rules(rule("secret", `C:\Windows\LogsSecret`)), []string{`C:\Windows\Logs`}, nil},
		{"Windows folds case for a root inside a rule", "windows",
			rules(data), []string{`c:\DATA\app`}, rules(rule("data", `c:\DATA\app`, "*.log"))},
		{"Windows folds case for a rule inside a root", "windows",
			rules(rule("logs", `C:\Windows\Logs`)), []string{`c:\windows`}, rules(rule("logs", `C:\Windows\Logs`))},
		{"a globbed rule inside a root is kept whole", "windows", rules(vendor), []string{`C:\ProgramData`}, rules(vendor)},
		{"a root inside a globbed rule", "windows",
			rules(vendor), []string{`C:\ProgramData\Veeam\Logs`}, rules(rule("vendor-logs", `C:\ProgramData\Veeam\Logs`, "*.log"))},
		{"a root below a globbed rule, in another case", "windows",
			rules(vendor), []string{`C:\ProgramData\veeam\logs\Sub`}, rules(rule("vendor-logs", `C:\ProgramData\veeam\logs\Sub`, "*.log"))},
		{"a root that only partly overlaps a globbed rule adds nothing", "windows",
			rules(vendor), []string{`C:\ProgramData\Veeam`}, nil},
		{"a root spelled as the rule's own glob keeps the rule", "windows",
			rules(vendor), []string{`C:\ProgramData\*\Logs`}, rules(vendor)},
		{"a globbed root containing a literal rule", "windows",
			rules(rule("veeam", `C:\ProgramData\Veeam\Logs`)), []string{`C:\ProgramData\*`}, rules(rule("veeam", `C:\ProgramData\Veeam\Logs`))},
		{"two different globs are never taken to contain each other", "windows",
			rules(rule("v", `C:\ProgramData\V*\Logs`)), []string{`C:\ProgramData\*\Logs`}, nil},
		// "[*]" matches the text "*", but covers only a directory named "*":
		// reading a glob as a name would keep the whole "/data/*" rule.
		{"a glob whose text another glob matches is not contained by it", "linux",
			rules(rule("sub", "/data/*")), []string{"/data/[*]"}, nil},
		{"a whole-drive rule narrows to the root", "windows",
			rules(rule("all", `C:\`)), []string{`C:\Users\bob`}, rules(rule("all", `C:\Users\bob`))},
		{"order and Files filters survive", "windows",
			rules(rule("data-logs", `C:\Data`, "*.log"), rule("data-all", `C:\Data`)), []string{`C:\Data\sub`},
			rules(rule("data-logs", `C:\Data\sub`, "*.log"), rule("data-all", `C:\Data\sub`))},
		{"several roots inside one rule", "windows",
			rules(rule("d", `C:\Data`)), []string{`C:\Data\a`, `C:\Other`, `C:\Data\b`},
			rules(rule("d", `C:\Data\a`), rule("d", `C:\Data\b`))},
		{"a rule kept whole is not repeated", "windows",
			rules(rule("app", `C:\Data\App`)), []string{`C:\Data`, `C:\Data\App\Sub`, `C:\`}, rules(rule("app", `C:\Data\App`))},
		{"malformed roots and rules add nothing", "windows",
			rules(rule("bad", `C:\Data\[`), rule("slashes", `C:/Data`), data), []string{`C:/Data`, `Data`, `C:\Data\..\Data`}, nil},
		{"Linux is case-sensitive", "linux", rules(rule("log", "/var/log")), []string{"/VAR/log"}, nil},
		{"the whole filesystem as a root", "linux", rules(rule("log", "/var/log")), []string{"/"}, rules(rule("log", "/var/log"))},
		{"the whole filesystem as a rule", "linux", rules(rule("all", "/")), []string{"/etc"}, rules(rule("all", "/etc"))},
		{"macOS folds case", "darwin",
			rules(rule("log", "/private/var/log")), []string{"/Private/Var"}, rules(rule("log", "/private/var/log"))},
		{"no roots, nothing allowed", "linux", rules(rule("all", "/")), nil, nil},
	}
	for _, c := range cases {
		if got := Narrow(c.goos, c.rules, c.roots); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Narrow(%s, %v, %q) =\n  %+v\nwant\n  %+v", c.name, c.goos, c.rules, c.roots, got, c.want)
		}
	}
}

// Narrow must never let a path through that the policy or the grant would
// refuse. Where every root and rule nest, it must also keep everything both
// allow: narrowing is not a licence to drop what the technician was granted.
func TestNarrowNeverWidens(t *testing.T) {
	policyRules := []proto.AllowRule{
		{ID: "win-logs", Path: `C:\Windows\Logs`},
		{ID: "setupapi", Path: `C:\Windows\INF`, Files: []string{"setupapi*.log"}},
		{ID: "vendor-logs", Path: `C:\ProgramData\*\Logs`, Files: []string{"*.log"}},
		{ID: "data", Path: `C:\Data`},
	}
	probes := []string{
		`C:\Windows\Logs\CBS\CBS.log`, `C:\Windows\INF\setupapi.dev.log`, `C:\Windows\INF\oem1.inf`,
		`C:\Windows\INF\sub\setupapi.x.log`, `C:\Windows\INF\sub\oem1.inf`, `C:\Windows\System32\drivers\etc\hosts`,
		`C:\ProgramData\Veeam\Logs\a.log`, `C:\ProgramData\Veeam\Logs\a.txt`, `C:\ProgramData\Veeam\secret.log`,
		`C:\ProgramData\Other\Logs\b.log`, `C:\Data\x\y.txt`, `C:\Data\z.txt`, `C:\Users\bob\notes.txt`, `D:\Data\z.txt`,
	}
	for _, c := range []struct {
		roots []string
		exact bool // every root and rule nest, so nothing both allow may be lost
	}{
		{[]string{`C:\`}, true},
		{[]string{`C:\Windows`}, true},
		{[]string{`C:\Windows\INF\sub`}, true},
		{[]string{`C:\ProgramData`}, true},
		{[]string{`C:\ProgramData\*`}, true},
		{[]string{`C:\ProgramData\Veeam\Logs`}, true},
		{[]string{`c:\data\x`, `C:\Users`}, true},
		{[]string{`C:\Users\bob`}, true},
		{[]string{`D:\`}, true},
		{[]string{`C:\ProgramData\Veeam`}, false}, // overlaps vendor-logs only partly
	} {
		grant := make([]proto.AllowRule, len(c.roots))
		for i, r := range c.roots {
			grant[i] = proto.AllowRule{ID: "grant", Path: r}
		}
		narrowed := Narrow("windows", policyRules, c.roots)
		for _, p := range probes {
			for _, isDir := range []bool{false, true} {
				_, _, got := MatchAllow("windows", narrowed, p, isDir)
				_, _, inPolicy := MatchAllow("windows", policyRules, p, isDir)
				_, _, inGrant := MatchAllow("windows", grant, p, isDir)
				if got && !(inPolicy && inGrant) {
					t.Errorf("roots %q: %q (dir=%v) is allowed after narrowing but policy=%v grant=%v", c.roots, p, isDir, inPolicy, inGrant)
				}
				if c.exact && !got && inPolicy && inGrant {
					t.Errorf("roots %q: narrowing lost %q (dir=%v), which both the policy and the grant allow", c.roots, p, isDir)
				}
			}
		}
	}
}
