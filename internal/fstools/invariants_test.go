package fstools

import (
	"embed"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Embed the production sources so this invariant still works when the test
// binary is cross-compiled on the Mac and run from a Windows laptop.
//
//go:embed *.go
var sourceFiles embed.FS

// writeCapable lists the files structured remediation is implemented in, the
// only files in this package allowed to refer to a writing API. They write
// solely under a Change capability, through a prepared and digest-matched
// plan, into a path that passed the read pipeline and the change-deny list.
// A new file that writes cannot appear without this list being edited.
var writeCapable = map[string]bool{
	"change.go":                 true,
	"change_ops.go":             true,
	"change_diff.go":            true,
	"change_unix.go":            true,
	"change_windows.go":         true,
	"change_service.go":         true,
	"change_service_windows.go": true,
	"change_service_linux.go":   true,
	"change_service_other.go":   true,
}

// Security invariant 6 as it stands after Slice 5: no read tool writes.
// Nothing in this package's sources, on any OS, refers to an API that
// creates, writes, renames, removes or re-permissions a file, or to an open
// flag that allows writing, outside the listed remediation files.
func TestNoWriteCapability(t *testing.T) {
	forbidden := map[string]bool{
		"Create": true, "OpenFile": false, "WriteFile": true, "WriteAt": true, "WriteString": true, "Write": true,
		"Remove": true, "RemoveAll": true, "Rename": true, "Mkdir": true, "MkdirAll": true, "Truncate": true,
		"Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true, "Symlink": true, "Link": true,
		"O_WRONLY": true, "O_RDWR": true, "O_CREATE": true, "O_APPEND": true, "O_TRUNC": true, "O_EXCL": true,
	}
	files, err := sourceFiles.ReadDir(".")
	if err != nil || len(files) == 0 {
		t.Fatalf("no embedded sources found: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range files {
		name := entry.Name()
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if writeCapable[name] {
			continue
		}
		if strings.HasPrefix(name, "change") {
			t.Errorf("%s looks like a remediation file but is not listed in writeCapable", name)
			continue
		}
		source, err := sourceFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && forbidden[sel.Sel.Name] {
				t.Errorf("%s: refers to %s", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

// Security invariant 5 on the live filesystem: a rule for the whole
// filesystem still cannot reach a hard-denied path, and listings hide them.
func TestCatchAllRuleCannotReachDeniedPaths(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, ".ssh", "id_ed25519"), "key")
	writeFile(t, filepath.Join(root, "id_rsa"), "key")
	var everything proto.AllowRule
	var denied, hiddenFromListing []string
	var listed string
	switch runtime.GOOS {
	case "windows":
		vol := filepath.VolumeName(root) + `\`
		everything = proto.AllowRule{ID: "everything", Path: vol}
		denied = []string{`C:\Windows\System32\config\SAM`, `C:\Windows\System32\config`}
		listed, hiddenFromListing = `C:\Windows\System32`, []string{"config"}
	case "darwin":
		everything = proto.AllowRule{ID: "everything", Path: "/"}
		denied = []string{"/etc/master.passwd", "/private/etc/master.passwd", "/dev/null", "/Library/Keychains"}
		listed, hiddenFromListing = "/", []string{"dev"}
	default:
		everything = proto.AllowRule{ID: "everything", Path: "/"}
		denied = []string{"/etc/shadow", "/proc/self/environ", "/root", "/dev/null"}
		listed, hiddenFromListing = "/", []string{"proc", "sys", "dev", "root"}
	}
	denied = append(denied, filepath.Join(root, ".ssh", "id_ed25519"), filepath.Join(root, ".ssh"), filepath.Join(root, "id_rsa"))
	x := New(Options{})
	pol := testPolicy(everything)
	for _, p := range denied {
		for _, op := range []string{proto.OpStat, proto.OpReadFile, proto.OpHashFile} {
			var args any = proto.StatArgs{Path: p}
			switch op {
			case proto.OpReadFile:
				args = proto.ReadFileArgs{Path: p}
			case proto.OpHashFile:
				args = proto.HashFileArgs{Path: p}
			}
			t.Run(fmt.Sprintf("%s %s", op, p), func(t *testing.T) {
				wantError(t, run(t, x, op, args, pol), proto.ErrHardDenied)
			})
		}
	}
	res := result[proto.ListDirResult](t, run(t, x, proto.OpListDir, proto.ListDirArgs{Path: listed}, pol))
	for _, name := range hiddenFromListing {
		if slices.Contains(entryNames(res.Entries), name) {
			t.Errorf("listing %s shows hard-denied %q", listed, name)
		}
	}
	if res.Omitted < len(hiddenFromListing) {
		t.Errorf("listing %s omitted %d entries; want at least %d", listed, res.Omitted, len(hiddenFromListing))
	}
}

// slowRedactor holds up the first redaction until the request deadline has
// passed, so the walk must notice the deadline part-way through.
type slowRedactor struct{ d time.Duration }

func (r slowRedactor) Redact(s string) (string, int, []string) {
	time.Sleep(r.d)
	return s, 0, nil
}

func TestWalksStopAtTheRequestDeadline(t *testing.T) {
	root := tempRoot(t)
	for i := range 50 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("d%02d", i), "app.log"), "ERROR line\n")
	}
	pol := testPolicy(rootRule(root))
	pol.Redact = true
	req := request(t, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, pol)
	req.Deadline = time.Now().Add(50 * time.Millisecond)
	start := time.Now()
	resp := New(Options{Redactor: slowRedactor{100 * time.Millisecond}}).Execute(t.Context(), req)
	wantError(t, resp, proto.ErrTimeout)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v to give up", elapsed)
	}
}
