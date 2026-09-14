package fstools

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func matchPaths(root string, matches []proto.FileInfo) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		rel, _ := filepath.Rel(root, m.Path)
		out[i] = filepath.ToSlash(rel)
	}
	return out
}

func TestSearchFiles(t *testing.T) {
	root := tempRoot(t)
	for _, p := range []string{"a.log", "notes.txt", "sub/b.log", "sub/deep/c.log", "sub/deep/deeper/d.log",
		".ssh/x.log", "sub/id_rsa.log"} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(p)), "x")
	}
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	cases := []struct {
		name      string
		pattern   string
		depth     int
		limit     int
		want      []string
		truncated bool
	}{
		{"every log", "*.log", 0, 0, []string{"a.log", "sub/b.log", "sub/deep/c.log", "sub/deep/deeper/d.log"}, false},
		{"depth 1", "*.log", 1, 0, []string{"a.log"}, false},
		{"depth 2", "*.log", 2, 0, []string{"a.log", "sub/b.log"}, false},
		{"limit", "*.log", 0, 2, []string{"a.log", "sub/b.log"}, true},
		{"other pattern", "*.txt", 0, 0, []string{"notes.txt"}, false},
		{"directories match too", "deep*", 0, 0, []string{"sub/deep", "sub/deep/deeper"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := run(t, x, proto.OpSearchFiles, proto.SearchFilesArgs{Path: root, Pattern: c.pattern, MaxDepth: c.depth, Limit: c.limit}, pol)
			res := result[proto.SearchFilesResult](t, resp)
			if got := matchPaths(root, res.Matches); !slices.Equal(got, c.want) || res.Truncated != c.truncated || res.Scanned == 0 {
				t.Errorf("search = %v truncated=%v scanned=%d; want %v truncated=%v", got, res.Truncated, res.Scanned, c.want, c.truncated)
			}
			for _, hidden := range []string{".ssh", "id_rsa"} {
				if bytes.Contains(resp.Result, []byte(hidden)) {
					t.Errorf("the result names hidden %q", hidden)
				}
			}
		})
	}
}

func TestSearchFilesNeverEntersDeniedDirectories(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "x")
	for i := range 10 {
		writeFile(t, filepath.Join(root, ".ssh", fmt.Sprintf("k%d.log", i)), "x")
	}
	res := result[proto.SearchFilesResult](t, run(t, New(Options{}), proto.OpSearchFiles,
		proto.SearchFilesArgs{Path: root, Pattern: "*"}, testPolicy(rootRule(root))))
	if res.Scanned != 2 || !slices.Equal(matchPaths(root, res.Matches), []string{"a.log"}) {
		t.Errorf("scanned %d entries, matches %v; the denied directory was entered", res.Scanned, matchPaths(root, res.Matches))
	}
}

func TestSearchFilesAppliesTheFilesFilter(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "x")
	writeFile(t, filepath.Join(root, "notes.txt"), "x")
	writeFile(t, filepath.Join(root, "sub", "b.log"), "x")
	resp := run(t, New(Options{}), proto.OpSearchFiles, proto.SearchFilesArgs{Path: root, Pattern: "*"}, testPolicy(rootRule(root, "*.log")))
	res := result[proto.SearchFilesResult](t, resp)
	if got := matchPaths(root, res.Matches); !slices.Equal(got, []string{"a.log", "sub", "sub/b.log"}) {
		t.Errorf("search = %v", got)
	}
	if bytes.Contains(resp.Result, []byte("notes.txt")) {
		t.Error("the result names a filtered file")
	}
}

func TestSearchFilesNeverFollowsLinks(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.log"), "x")
	writeFile(t, filepath.Join(root, "a.log"), "x")
	symlinkOrSkip(t, outside, filepath.Join(root, "linkdir"))
	symlinkOrSkip(t, filepath.Join(outside, "secret.log"), filepath.Join(root, "link.log"))
	resp := run(t, New(Options{}), proto.OpSearchFiles, proto.SearchFilesArgs{Path: root, Pattern: "*.log"}, testPolicy(rootRule(root)))
	res := result[proto.SearchFilesResult](t, resp)
	if got := matchPaths(root, res.Matches); !slices.Equal(got, []string{"a.log", "link.log"}) {
		t.Fatalf("search = %v", got)
	}
	if res.Matches[1].Type != proto.TypeSymlink || bytes.Contains(resp.Result, []byte("secret")) {
		t.Errorf("a link was followed: %s", resp.Result)
	}
}

func TestSearchFilesRefusals(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "x")
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	wantError(t, run(t, x, proto.OpSearchFiles, proto.SearchFilesArgs{Path: root, Pattern: "[a"}, pol), proto.ErrBadRequest)
	wantError(t, run(t, x, proto.OpSearchFiles, proto.SearchFilesArgs{Path: root}, pol), proto.ErrBadRequest)
	wantError(t, run(t, x, proto.OpSearchFiles, proto.SearchFilesArgs{Path: filepath.Join(root, "a.log"), Pattern: "*"}, pol), proto.ErrNotRegular)
}
