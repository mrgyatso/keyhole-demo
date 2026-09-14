package fstools

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func entryNames(entries []proto.FileInfo) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	return names
}

func TestListDirShowsAllowedEntriesAndCountsTheRest(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "b.log"), "b")
	writeFile(t, filepath.Join(root, "a.log"), "aa")
	writeFile(t, filepath.Join(root, "notes.txt"), "n")
	mkdir(t, filepath.Join(root, "sub"))
	writeFile(t, filepath.Join(root, "id_rsa"), "k")
	mkdir(t, filepath.Join(root, ".ssh"))
	writeFile(t, filepath.Join(root, "server.pem"), "k")
	x := New(Options{})

	cases := []struct {
		name       string
		files      []string
		limit, cap int
		want       []string
		hidden     []string
		omitted    int
		truncated  bool
	}{
		{"everything allowed", nil, 0, 0, []string{"a.log", "b.log", "notes.txt", "sub"}, nil, 3, false},
		{"files filter", []string{"*.log"}, 0, 0, []string{"a.log", "b.log", "sub"}, []string{"notes.txt"}, 4, false},
		{"request limit", nil, 2, 0, []string{"a.log", "b.log"}, nil, 3, true},
		{"policy cap", nil, 0, 2, []string{"a.log", "b.log"}, nil, 3, true},
		{"limit above the cap", nil, 50, 3, []string{"a.log", "b.log", "notes.txt"}, nil, 3, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol := testPolicy(rootRule(root, c.files...))
			if c.cap > 0 {
				pol.MaxListEntries = c.cap
			}
			resp := run(t, x, proto.OpListDir, proto.ListDirArgs{Path: root, Limit: c.limit}, pol)
			res := result[proto.ListDirResult](t, resp)
			if got := entryNames(res.Entries); !slices.Equal(got, c.want) || res.Omitted != c.omitted || res.Truncated != c.truncated || res.Path != root {
				t.Errorf("list = %v omitted=%d truncated=%v path=%q; want %v omitted=%d truncated=%v",
					got, res.Omitted, res.Truncated, res.Path, c.want, c.omitted, c.truncated)
			}
			for _, name := range append([]string{"id_rsa", ".ssh", "server.pem"}, c.hidden...) {
				if bytes.Contains(resp.Result, []byte(name)) {
					t.Errorf("the result names hidden entry %q", name)
				}
			}
		})
	}
}

func TestListDirDescribesEntries(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "aa")
	mkdir(t, filepath.Join(root, "sub"))
	res := result[proto.ListDirResult](t, run(t, New(Options{}), proto.OpListDir, proto.ListDirArgs{Path: root}, testPolicy(rootRule(root))))
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %+v", res.Entries)
	}
	a, sub := res.Entries[0], res.Entries[1]
	if a.Type != proto.TypeFile || a.Size != 2 || a.Path != filepath.Join(root, "a.log") || a.ModTime.IsZero() {
		t.Errorf("file entry = %+v", a)
	}
	if sub.Type != proto.TypeDir || sub.Size != 0 || sub.Path != filepath.Join(root, "sub") {
		t.Errorf("dir entry = %+v", sub)
	}
}

func TestListDirShowsLinksWithoutFollowing(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside")
	symlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.log"))
	symlinkOrSkip(t, outside, filepath.Join(root, "dirlink"))
	symlinkOrSkip(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "id_rsa_link"))
	resp := run(t, New(Options{}), proto.OpListDir, proto.ListDirArgs{Path: root}, testPolicy(rootRule(root)))
	res := result[proto.ListDirResult](t, resp)
	if got := entryNames(res.Entries); !slices.Equal(got, []string{"dirlink", "escape.log"}) || res.Omitted != 1 {
		t.Fatalf("list = %v omitted=%d", got, res.Omitted)
	}
	for _, e := range res.Entries {
		if e.Type != proto.TypeSymlink {
			t.Errorf("%s: type %q; want symlink", e.Name, e.Type)
		}
	}
	if bytes.Contains(resp.Result, []byte("secret.txt")) {
		t.Error("a link was followed")
	}
}

func TestListDirRefusals(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "aa")
	mkdir(t, filepath.Join(root, ".ssh"))
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	wantError(t, run(t, x, proto.OpListDir, proto.ListDirArgs{Path: filepath.Join(root, "a.log")}, pol), proto.ErrNotRegular)
	wantError(t, run(t, x, proto.OpListDir, proto.ListDirArgs{Path: filepath.Dir(root)}, pol), proto.ErrNotAllowed)
	wantError(t, run(t, x, proto.OpListDir, proto.ListDirArgs{Path: filepath.Join(root, ".ssh")}, pol), proto.ErrHardDenied)
}
