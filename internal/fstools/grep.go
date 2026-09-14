package fstools

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// maxLineBytes bounds how much of one line grep holds and matches against;
// the rest of a longer line is not searched.
const maxLineBytes = 1 << 20

func (c *call) grep(a proto.GrepArgs) (proto.GrepResult, error) {
	if a.Pattern == "" {
		return proto.GrepResult{}, failf(proto.ErrBadRequest, "pattern is required")
	}
	expr := a.Pattern
	if a.IgnoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return proto.GrepResult{}, failf(proto.ErrBadRequest, "bad regular expression (RE2 syntax): %v", err)
	}
	if a.Glob != "" {
		if _, err := policy.MatchName(c.goos, a.Glob, ""); err != nil {
			return proto.GrepResult{}, failf(proto.ErrBadRequest, "bad glob %q: %v", a.Glob, err)
		}
	}
	t, err := c.open(a.Path)
	if err != nil {
		return proto.GrepResult{}, err
	}
	defer t.close()

	g := &grepper{c: c, re: re, limit: clampLimit(a.MaxMatches, c.caps.maxMatches)}
	g.res.Matches = []proto.GrepMatch{}
	if t.info.IsDir() {
		err = c.walk(t, walkDepth(a.MaxDepth), g.visitor(t, a.Glob))
	} else if err = g.searchFile(t.file, t.info, t.path); errors.Is(err, errStop) {
		err = nil
	}
	if err != nil {
		return proto.GrepResult{}, err
	}
	slices.SortFunc(g.res.Matches, func(a, b proto.GrepMatch) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line))
	})
	return g.res, nil
}

type grepper struct {
	c     *call
	re    *regexp.Regexp
	limit int
	res   proto.GrepResult
	line  []byte // reused line buffer
}

// visitor searches every allowed regular file whose name passes glob and
// descends into every allowed directory.
func (g *grepper) visitor(t *target, glob string) visitFn {
	rules := g.c.allowRules()
	return func(p, rel string, info fs.FileInfo, _ int) (bool, error) {
		switch {
		case isLink(info):
			return false, nil
		case info.IsDir():
			return policy.Decide(g.c.goos, rules, p, true).Allowed, nil
		case !info.Mode().IsRegular() || !policy.Decide(g.c.goos, rules, p, false).Allowed:
			return false, nil
		}
		if glob != "" {
			if ok, _ := policy.MatchName(g.c.goos, glob, info.Name()); !ok {
				return false, nil
			}
		}
		if g.res.FilesScanned+g.res.FilesSkipped >= proto.GrepMaxFiles {
			g.res.Truncated = true
			return false, errStop
		}
		f, fi, err := g.c.openVerified(t, rel, p, false)
		if err != nil {
			g.res.FilesSkipped++
			return false, nil
		}
		defer f.Close()
		return false, g.searchFile(f, fi, p)
	}
}

// searchFile matches the file's lines, skipping binary files and files
// over the policy's size cap. UTF-16 files are decoded first.
func (g *grepper) searchFile(f *os.File, fi fs.FileInfo, p string) error {
	size := fi.Size()
	if size > g.c.caps.maxFile {
		g.res.FilesSkipped++
		return nil
	}
	head, err := readAt(f, 0, min(size, sniffBytes))
	enc := sniff(head)
	if err != nil || enc == encBinary {
		g.res.FilesSkipped++
		return nil
	}
	g.res.FilesScanned++
	var r io.Reader = io.NewSectionReader(f, 0, size)
	if enc != encUTF8 {
		r = newUTF16Reader(io.NewSectionReader(f, 2, size-2), enc.order())
	}
	br := bufio.NewReaderSize(r, 64<<10)
	for n := 1; ; n++ {
		if n%1024 == 0 {
			if err := g.c.ctx.Err(); err != nil {
				return err
			}
		}
		line, err := g.readLine(br)
		if len(line) > 0 || err == nil {
			if merr := g.match(p, n, line); merr != nil {
				return merr
			}
		}
		if err != nil {
			return nil // end of file, or unreadable from here on: keep what matched
		}
	}
}

// readLine returns the next line without its line ending, holding at most
// maxLineBytes of it.
func (g *grepper) readLine(br *bufio.Reader) ([]byte, error) {
	line := g.line[:0]
	for {
		chunk, err := br.ReadSlice('\n')
		if room := maxLineBytes - len(line); room > 0 {
			line = append(line, chunk[:min(len(chunk), room)]...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		g.line = line
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		return line, err
	}
}

// match records line if it matches. The regular expression must still
// match after redaction, so a pattern cannot probe for a secret that the
// redactor hides: grep sees exactly what read_file would show.
func (g *grepper) match(p string, n int, line []byte) error {
	if !g.re.Match(line) {
		return nil
	}
	text, count, rules := g.c.redact(strings.ToValidUTF8(string(line), "�"))
	if count > 0 && !g.re.MatchString(text) {
		return nil
	}
	if len(g.res.Matches) == g.limit {
		g.res.Truncated = true
		return errStop
	}
	g.c.noteRedactions(count, rules)
	g.res.Matches = append(g.res.Matches, proto.GrepMatch{Path: p, Line: n, Text: truncateUTF8(text, proto.GrepMaxLineBytes)})
	return nil
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
