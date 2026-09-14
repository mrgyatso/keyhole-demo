package fstools

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// These tests exercise the Windows-only bypass shapes on a real NTFS
// volume. They run on the Windows Server test VM.

// mklinkJunction creates a directory junction; unlike a symlink it needs no
// privilege.
func mklinkJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
}

// wantRefusal accepts any of codes: how a junction is refused (os.Root
// declining it, or the final-path check) may vary with the Go release.
func wantRefusal(t *testing.T, resp *proto.Response, codes ...string) {
	t.Helper()
	if resp.OK || resp.Error == nil || !slices.Contains(codes, resp.Error.Code) || len(resp.Result) != 0 {
		t.Fatalf("got ok=%v error=%+v; want one of %v", resp.OK, resp.Error, codes)
	}
}

func TestJunctionOutOfTheRootIsRefused(t *testing.T) {
	root, outside := tempRoot(t), tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.log"), "outside the rule")
	writeFile(t, filepath.Join(root, "a.log"), "inside")
	mklinkJunction(t, filepath.Join(root, "j"), outside)
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	wantRefusal(t, run(t, x, proto.OpStat, proto.StatArgs{Path: filepath.Join(root, "j")}, pol), proto.ErrUnsafePath)
	wantRefusal(t, run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: filepath.Join(root, "j", "secret.log")}, pol), proto.ErrUnsafePath)

	resp := run(t, x, proto.OpListDir, proto.ListDirArgs{Path: root}, pol)
	res := result[proto.ListDirResult](t, resp)
	if got := entryNames(res.Entries); !slices.Equal(got, []string{"a.log", "j"}) || res.Entries[1].Type != proto.TypeSymlink {
		t.Errorf("list = %+v; want the junction shown as a link", res.Entries)
	}
	search := result[proto.SearchFilesResult](t, run(t, x, proto.OpSearchFiles, proto.SearchFilesArgs{Path: root, Pattern: "*.log"}, pol))
	grep := result[proto.GrepResult](t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "outside"}, pol))
	if len(search.Matches) != 1 || len(grep.Matches) != 0 {
		t.Errorf("a walk followed the junction: search %+v grep %+v", search.Matches, grep.Matches)
	}
}

func TestJunctionToADeniedDirectoryInsideTheRootIsRefused(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, ".ssh", "config.log"), "Host x")
	mklinkJunction(t, filepath.Join(root, "innocent"), filepath.Join(root, ".ssh"))
	resp := run(t, New(Options{}), proto.OpReadFile, proto.ReadFileArgs{Path: filepath.Join(root, "innocent", "config.log")}, testPolicy(rootRule(root)))
	wantRefusal(t, resp, proto.ErrHardDenied, proto.ErrUnsafePath)
}

func TestRuleRootThatIsAJunctionIsJudgedByItsFinalPath(t *testing.T) {
	base, outside := tempRoot(t), tempRoot(t)
	writeFile(t, filepath.Join(outside, "app.log"), "x")
	mklinkJunction(t, filepath.Join(base, "logs"), outside)
	pol := testPolicy(proto.AllowRule{ID: "junction-rule", Path: filepath.Join(base, "logs")})
	resp := run(t, New(Options{}), proto.OpReadFile, proto.ReadFileArgs{Path: filepath.Join(base, "logs", "app.log")}, pol)
	wantRefusal(t, resp, proto.ErrUnsafePath)
}

func TestAlternateDataStreamsAreRefused(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.log")
	writeFile(t, p, "visible")
	if err := os.WriteFile(p+":secret", []byte("hidden stream"), 0o644); err != nil {
		t.Skipf("no alternate data streams here: %v", err)
	}
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	for _, q := range []string{p + ":secret", p + "::$DATA", p + ":secret:$DATA"} {
		wantError(t, run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: q}, pol), proto.ErrUnsafePath)
	}
	if r := result[proto.ReadFileResult](t, run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: p}, pol)); r.Content != "visible" {
		t.Errorf("main stream = %q", r.Content)
	}
	if g := result[proto.GrepResult](t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "hidden"}, pol)); len(g.Matches) != 0 {
		t.Errorf("grep reached the stream: %+v", g.Matches)
	}
}

func shortPath(t *testing.T, p string) string {
	t.Helper()
	from, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(from, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Skipf("GetShortPathName: %v", err)
	}
	return windows.UTF16ToString(buf[:n])
}

func TestShortNamesAreRefused(t *testing.T) {
	root := tempRoot(t)
	long := filepath.Join(root, "LongDirectoryName")
	writeFile(t, filepath.Join(long, "app.log"), "x")
	short := shortPath(t, long)
	if strings.EqualFold(short, long) {
		t.Skip("8.3 names are disabled on this volume")
	}
	wantError(t, run(t, New(Options{}), proto.OpReadFile, proto.ReadFileArgs{Path: filepath.Join(short, "app.log")}, testPolicy(rootRule(root))), proto.ErrUnsafePath)
}

func TestWindowsPathFormsAreRefused(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.log")
	writeFile(t, p, "x")
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	for _, q := range []string{
		`\\?\` + p,
		`\\.\` + p,
		`\\localhost\` + strings.Replace(p, ":", "$", 1),
		strings.ReplaceAll(p, `\`, "/"),
		filepath.Join(root, "NUL"),
		filepath.Join(root, "CON.log"),
		p + ".",
		p + " ",
	} {
		wantError(t, run(t, x, proto.OpStat, proto.StatArgs{Path: q}, pol), proto.ErrUnsafePath)
	}
}

func TestMatchingIsCaseInsensitive(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "Sub", "App.LOG"), "x")
	writeFile(t, filepath.Join(root, ".SSH", "KEY.log"), "k")
	x := New(Options{})
	pol := testPolicy(rootRule(root, "*.log"))
	resp := run(t, x, proto.OpStat, proto.StatArgs{Path: strings.ToUpper(filepath.Join(root, "sub", "app.log"))}, pol)
	if st := result[proto.StatResult](t, resp); st.Path != filepath.Join(root, "Sub", "App.LOG") {
		t.Errorf("stat path = %q; want the on-disk spelling", st.Path)
	}
	wantError(t, run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: filepath.Join(root, ".ssh", "key.log")}, pol), proto.ErrHardDenied)
}
