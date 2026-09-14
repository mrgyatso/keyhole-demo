package fstools

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func grepLines(root string, matches []proto.GrepMatch) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		rel, _ := filepath.Rel(root, m.Path)
		out[i] = fmt.Sprintf("%s:%d:%s", filepath.ToSlash(rel), m.Line, m.Text)
	}
	return out
}

func TestGrep(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.log"), "INFO start\r\nERROR disk full\r\ninfo done")
	writeFile(t, filepath.Join(root, "sub", "b.log"), "error: again\nok\n")
	writeFile(t, filepath.Join(root, "sub", "c.txt"), "ERROR in txt\n")
	writeFile(t, filepath.Join(root, ".ssh", "x.log"), "ERROR hidden\n")
	writeFile(t, filepath.Join(root, "bin.dat"), "ERROR\x00binary")
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	cases := []struct {
		name      string
		args      proto.GrepArgs
		want      []string
		skipped   int
		truncated bool
	}{
		{"directory", proto.GrepArgs{Path: root, Pattern: "ERROR"},
			[]string{"a.log:2:ERROR disk full", "sub/c.txt:1:ERROR in txt"}, 1, false},
		{"ignore case", proto.GrepArgs{Path: root, Pattern: "error", IgnoreCase: true},
			[]string{"a.log:2:ERROR disk full", "sub/b.log:1:error: again", "sub/c.txt:1:ERROR in txt"}, 1, false},
		{"glob", proto.GrepArgs{Path: root, Pattern: "error", IgnoreCase: true, Glob: "*.log"},
			[]string{"a.log:2:ERROR disk full", "sub/b.log:1:error: again"}, 0, false},
		{"depth", proto.GrepArgs{Path: root, Pattern: "ERROR", MaxDepth: 1},
			[]string{"a.log:2:ERROR disk full"}, 1, false},
		{"single file", proto.GrepArgs{Path: filepath.Join(root, "a.log"), Pattern: "done$"},
			[]string{"a.log:3:info done"}, 0, false},
		{"max matches", proto.GrepArgs{Path: root, Pattern: "ERROR", MaxMatches: 1},
			[]string{"a.log:2:ERROR disk full"}, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := run(t, x, proto.OpGrep, c.args, pol)
			res := result[proto.GrepResult](t, resp)
			if got := grepLines(root, res.Matches); !slices.Equal(got, c.want) || res.FilesSkipped != c.skipped || res.Truncated != c.truncated {
				t.Errorf("grep = %q skipped=%d truncated=%v; want %q skipped=%d truncated=%v",
					got, res.FilesSkipped, res.Truncated, c.want, c.skipped, c.truncated)
			}
			if bytes.Contains(resp.Result, []byte("hidden")) {
				t.Error("grep read a hard-denied file")
			}
		})
	}

	capped := testPolicy(rootRule(root))
	capped.MaxMatches = 1
	res := result[proto.GrepResult](t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR", MaxMatches: 10}, capped))
	if len(res.Matches) != 1 || !res.Truncated {
		t.Errorf("policy cap: %d matches, truncated=%v", len(res.Matches), res.Truncated)
	}
	wantError(t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "("}, pol), proto.ErrBadRequest)
	wantError(t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "x", Glob: "[a"}, pol), proto.ErrBadRequest)
	wantError(t, run(t, x, proto.OpGrep, proto.GrepArgs{Path: root}, pol), proto.ErrBadRequest)
}

func TestGrepSkipsFilesOverTheSizeCap(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "big.log"), "ERROR and then some more\n")
	writeFile(t, filepath.Join(root, "small.log"), "ERROR\n")
	pol := testPolicy(rootRule(root))
	pol.MaxFileBytes = 10
	res := result[proto.GrepResult](t, run(t, New(Options{}), proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, pol))
	if got := grepLines(root, res.Matches); !slices.Equal(got, []string{"small.log:1:ERROR"}) || res.FilesSkipped != 1 || res.FilesScanned != 1 {
		t.Errorf("grep = %q scanned=%d skipped=%d", got, res.FilesScanned, res.FilesSkipped)
	}
}

func TestGrepTruncatesLongLinesOnRuneBoundaries(t *testing.T) {
	root := tempRoot(t)
	line := "ERROR " + strings.Repeat("é", proto.GrepMaxLineBytes) // two bytes per é: the cap falls mid-rune
	writeFile(t, filepath.Join(root, "long.log"), line+"\n")
	res := result[proto.GrepResult](t, run(t, New(Options{}), proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, testPolicy(rootRule(root))))
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %d", len(res.Matches))
	}
	text := res.Matches[0].Text
	if len(text) > proto.GrepMaxLineBytes || len(text) < proto.GrepMaxLineBytes-1 || !utf8.ValidString(text) || !strings.HasPrefix(text, "ERROR é") {
		t.Errorf("truncated line: %d bytes, valid=%v", len(text), utf8.ValidString(text))
	}
}

func TestGrepRedactsLinesAndCannotProbeSecrets(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "app.config"), "password=hunter2\nuser=hunter2 ERROR\nplain ERROR\n")
	x := New(Options{Redactor: fakeRedactor{"hunter2"}})
	pol := testPolicy(rootRule(root))
	pol.Redact = true

	resp := run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, pol)
	res := result[proto.GrepResult](t, resp)
	want := []string{"app.config:2:user=[REDACTED:test-secret] ERROR", "app.config:3:plain ERROR"}
	if got := grepLines(root, res.Matches); !slices.Equal(got, want) {
		t.Errorf("grep = %q; want %q", got, want)
	}
	if resp.Meta.Redactions != 1 || !slices.Equal(resp.Meta.RedactionRules, []string{"test-secret"}) {
		t.Errorf("meta = %+v", resp.Meta)
	}

	for _, probe := range []string{"hunter2", "password=hunt", "hunter[0-9]"} {
		resp := run(t, x, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: probe}, pol)
		if res := result[proto.GrepResult](t, resp); len(res.Matches) != 0 || resp.Meta.Redactions != 0 {
			t.Errorf("probe %q found %q", probe, grepLines(root, res.Matches))
		}
	}
}

func TestGrepDecodesUTF16(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "setup.log"), utf16File(binary.LittleEndian, "hello\r\nERROR 😀 x\r\nbye\r\n"))
	res := result[proto.GrepResult](t, run(t, New(Options{}), proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, testPolicy(rootRule(root))))
	if got := grepLines(root, res.Matches); !slices.Equal(got, []string{"setup.log:2:ERROR 😀 x"}) || res.FilesScanned != 1 {
		t.Errorf("grep = %q", got)
	}
}

func TestGrepNeverFollowsLinks(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.log"), "ERROR outside\n")
	writeFile(t, filepath.Join(root, "a.log"), "ERROR inside\n")
	symlinkOrSkip(t, outside, filepath.Join(root, "linkdir"))
	symlinkOrSkip(t, filepath.Join(outside, "secret.log"), filepath.Join(root, "link.log"))
	res := result[proto.GrepResult](t, run(t, New(Options{}), proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR"}, testPolicy(rootRule(root))))
	if got := grepLines(root, res.Matches); !slices.Equal(got, []string{"a.log:1:ERROR inside"}) {
		t.Errorf("grep = %q", got)
	}
}

func TestGrepCapsTheFilesItExamines(t *testing.T) {
	root := tempRoot(t)
	for i := range proto.GrepMaxFiles + 1 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("f%05d.log", i)), "x\n")
	}
	res := result[proto.GrepResult](t, run(t, New(Options{}), proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "nomatch"}, testPolicy(rootRule(root))))
	if res.FilesScanned+res.FilesSkipped != proto.GrepMaxFiles || !res.Truncated {
		t.Errorf("examined %d files, truncated=%v; want %d and truncated", res.FilesScanned+res.FilesSkipped, res.Truncated, proto.GrepMaxFiles)
	}
}

// cancelRedactor cancels the call's context the first time it runs, so the
// walk must notice mid-way.
type cancelRedactor struct {
	once   *sync.Once
	cancel context.CancelFunc
}

func (r cancelRedactor) Redact(s string) (string, int, []string) {
	r.once.Do(r.cancel)
	return s, 0, nil
}

func TestGrepStopsWhenCancelledMidWalk(t *testing.T) {
	root := tempRoot(t)
	for i := range 200 {
		writeFile(t, filepath.Join(root, fmt.Sprintf("d%03d", i), "app.log"), strings.Repeat("ERROR line\n", 2000))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := New(Options{Redactor: cancelRedactor{&sync.Once{}, cancel}})
	pol := testPolicy(rootRule(root))
	pol.Redact = true
	pol.MaxMatches = 1 << 30
	resp := x.Execute(ctx, request(t, proto.OpGrep, proto.GrepArgs{Path: root, Pattern: "ERROR", MaxMatches: 1 << 30}, pol))
	wantError(t, resp, proto.ErrTimeout)
}
