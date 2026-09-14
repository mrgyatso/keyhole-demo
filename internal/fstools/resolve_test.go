package fstools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func TestStatFileAndDirectory(t *testing.T) {
	root := tempRoot(t)
	logs := filepath.Join(root, "logs")
	writeFile(t, filepath.Join(logs, "app.log"), "hello\n")
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	resp := run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(logs, "app.log")}, pol)
	st := result[proto.StatResult](t, resp)
	if st.Type != proto.TypeFile || st.Size != 6 || st.Name != "app.log" || st.Path != filepath.Join(logs, "app.log") || st.Mode == "" {
		t.Errorf("stat file = %+v", st)
	}
	if resp.Meta.RuleID != "test-root" || resp.Meta.ResolvedPath != st.Path {
		t.Errorf("meta = %+v", resp.Meta)
	}

	dir := result[proto.StatResult](t, run(t, x, proto.OpStat, proto.StatArgs{Path: logs}, pol))
	if dir.Type != proto.TypeDir || dir.Path != logs {
		t.Errorf("stat dir = %+v", dir)
	}
	top := result[proto.StatResult](t, run(t, x, proto.OpStat, proto.StatArgs{Path: root}, pol))
	if top.Type != proto.TypeDir || top.Path != root || top.Name != filepath.Base(root) {
		t.Errorf("stat rule root = %+v", top)
	}
}

func TestMetaCoversTheExactResultBytes(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "x")
	resp := run(t, New(Options{}), proto.OpStat, proto.StatArgs{Path: filepath.Join(root, "a.log")}, testPolicy(rootRule(root)))
	sum := sha256.Sum256(resp.Result)
	if !resp.OK || resp.Meta.Bytes != int64(len(resp.Result)) || resp.Meta.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("meta %+v does not cover result %s", resp.Meta, resp.Result)
	}
}

func TestResolutionRefusals(t *testing.T) {
	root := tempRoot(t)
	logs := filepath.Join(root, "logs")
	writeFile(t, filepath.Join(logs, "app.log"), "hello\n")
	writeFile(t, filepath.Join(logs, "notes.txt"), "notes")
	writeFile(t, filepath.Join(logs, "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----")
	writeFile(t, root+"Secret"+string(filepath.Separator)+"x.log", "sibling") // the rule root as a string prefix
	sep := string(filepath.Separator)
	x := New(Options{})

	cases := []struct {
		name, path string
		files      []string
		code       string
	}{
		{"above the rule", filepath.Dir(root), nil, proto.ErrNotAllowed},
		{"sibling sharing the root as a string prefix", root + "Secret" + sep + "x.log", nil, proto.ErrNotAllowed},
		{"missing inside the rule", filepath.Join(logs, "nope.log"), nil, proto.ErrNotFound},
		{"missing below a missing dir", filepath.Join(logs, "no", "such", "file.log"), nil, proto.ErrNotFound},
		{"missing outside every rule", root + "Secret" + sep + "nope.log", nil, proto.ErrNotAllowed},
		{"traversal", logs + sep + ".." + sep + "logs" + sep + "app.log", nil, proto.ErrUnsafePath},
		{"relative", "logs" + sep + "app.log", nil, proto.ErrUnsafePath},
		{"empty segment", logs + sep + sep + "app.log", nil, proto.ErrUnsafePath},
		{"hard-denied inside the rule", filepath.Join(logs, "id_rsa"), nil, proto.ErrHardDenied},
		{"filtered out by Files", filepath.Join(logs, "notes.txt"), []string{"*.log"}, proto.ErrNotAllowed},
		{"empty path", "", nil, proto.ErrBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := run(t, x, proto.OpStat, proto.StatArgs{Path: c.path}, testPolicy(rootRule(root, c.files...)))
			wantError(t, resp, c.code)
		})
	}

	resp := run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(logs, "id_rsa")}, testPolicy(rootRule(root)))
	if resp.Meta.RuleID != "deny-ssh-keys" {
		t.Errorf("hard-denied meta.rule_id = %q; want the deny rule for the audit log", resp.Meta.RuleID)
	}
}

func TestSymlinksCannotWidenAccess(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	logs := filepath.Join(root, "logs")
	writeFile(t, filepath.Join(logs, "app.log"), "hello\n")
	writeFile(t, filepath.Join(logs, "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----")
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside the rule")
	symlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(logs, "escape.log"))
	symlinkOrSkip(t, filepath.Join(logs, "id_rsa"), filepath.Join(logs, "innocent.log"))
	symlinkOrSkip(t, outside, filepath.Join(logs, "linkdir"))
	symlinkOrSkip(t, filepath.Join("..", "..", filepath.Base(outside), "secret.txt"), filepath.Join(logs, "relative.log"))
	symlinkOrSkip(t, filepath.Join(logs, "app.log"), filepath.Join(logs, "alias.log"))
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	for name, c := range map[string]struct{ path, code string }{
		"file link to outside the root":     {filepath.Join(logs, "escape.log"), proto.ErrUnsafePath},
		"relative file link out":            {filepath.Join(logs, "relative.log"), proto.ErrUnsafePath},
		"link to a hard-denied name inside": {filepath.Join(logs, "innocent.log"), proto.ErrHardDenied},
		"directory link to outside":         {filepath.Join(logs, "linkdir"), proto.ErrUnsafePath},
		"through a directory link":          {filepath.Join(logs, "linkdir", "secret.txt"), proto.ErrUnsafePath},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, run(t, x, proto.OpStat, proto.StatArgs{Path: c.path}, pol), c.code)
		})
	}

	// A link that stays inside the rule is followed, and the audit sees the target.
	resp := run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(logs, "alias.log")}, pol)
	st := result[proto.StatResult](t, resp)
	if st.Path != filepath.Join(logs, "app.log") || resp.Meta.ResolvedPath != st.Path {
		t.Errorf("in-rule link: path %q, resolved %q; want the target", st.Path, resp.Meta.ResolvedPath)
	}
}

func TestRulesMatchCanonicalPaths(t *testing.T) {
	base := tempRoot(t)
	real := filepath.Join(base, "real")
	writeFile(t, filepath.Join(real, "app.log"), "hello\n")
	symlinkOrSkip(t, real, filepath.Join(base, "link"))
	x := New(Options{})
	// The rule names the symlinked spelling, as /var/log does on macOS.
	pol := testPolicy(proto.AllowRule{ID: "via-link", Path: filepath.Join(base, "link")})

	for _, p := range []string{filepath.Join(real, "app.log"), filepath.Join(base, "link", "app.log")} {
		resp := run(t, x, proto.OpStat, proto.StatArgs{Path: p}, pol)
		st := result[proto.StatResult](t, resp)
		if st.Path != filepath.Join(real, "app.log") || resp.Meta.RuleID != "via-link" {
			t.Errorf("stat %q = %q via %q", p, st.Path, resp.Meta.RuleID)
		}
	}
}

func TestRuleNamingAFileIsRefused(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "app.log"), "x")
	pol := testPolicy(proto.AllowRule{ID: "file-rule", Path: filepath.Join(root, "app.log")})
	resp := run(t, New(Options{}), proto.OpStat, proto.StatArgs{Path: filepath.Join(root, "app.log")}, pol)
	wantError(t, resp, proto.ErrNotAllowed)
}

func TestNoExistenceOracleOutsideRules(t *testing.T) {
	root := tempRoot(t)
	other := tempRoot(t)
	writeFile(t, filepath.Join(other, "exists.txt"), "x")
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	a := run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(other, "exists.txt")}, pol)
	b := run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(other, "missing.txt")}, pol)
	wantError(t, a, proto.ErrNotAllowed)
	wantError(t, b, proto.ErrNotAllowed)
	if _, err := os.Stat(filepath.Join(other, "exists.txt")); err != nil {
		t.Fatal(err)
	}
}
