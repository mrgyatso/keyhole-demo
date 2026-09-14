package fstools

import (
	"fmt"
	"strings"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// The diff is what a person approves, so it is a real unified diff, bounded
// on both axes: at most proto.MaxChangeDiffLines lines and
// proto.MaxChangeDiffBytes bytes, and the line-by-line comparison itself is
// only run when the changed region is small enough to compare exactly.
// Anything larger is shown honestly as a wholesale replacement rather than
// guessed at.
const (
	diffContext  = 3
	maxDiffCells = 1 << 20 // longest-common-subsequence table entries
)

type editKind byte

const (
	keep editKind = ' '
	del  editKind = '-'
	add  editKind = '+'
)

type edit struct {
	kind editKind
	text string
}

// unifiedDiff renders before -> after as a unified diff of path. lines is the
// number of diff lines produced and truncated says whether a ceiling cut it
// short.
func unifiedDiff(before, after, path string) (string, int, bool) {
	a, aNL := splitLines(before)
	b, bNL := splitLines(after)
	edits := diffLines(a, b)

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", path, path)
	lines, truncated := 2, false
	emit := func(s string) bool {
		if lines >= proto.MaxChangeDiffLines || out.Len()+len(s) > proto.MaxChangeDiffBytes {
			truncated = true
			return false
		}
		out.WriteString(s)
		lines++
		return true
	}

	aLine, bLine := 1, 1 // 1-based line numbers of the next unconsumed line
	for i := 0; i < len(edits) && !truncated; {
		if edits[i].kind == keep {
			aLine, bLine = aLine+1, bLine+1
			i++
			continue
		}
		// A hunk starts up to diffContext lines before the first change and
		// ends diffContext unchanged lines after the last one. Changes closer
		// together than twice the context share one hunk, so no line is ever
		// printed twice.
		start := countKeepBefore(edits, i, diffContext)
		lead := i - start
		end, runStart := i, -1
		for end < len(edits) {
			if edits[end].kind == keep {
				if runStart < 0 {
					runStart = end
				}
				if end-runStart+1 > 2*diffContext {
					break
				}
			} else {
				runStart = -1
			}
			end++
		}
		if runStart >= 0 {
			end = min(end, runStart+diffContext)
		}
		aStart, bStart := aLine-lead, bLine-lead
		var aCount, bCount int
		for _, e := range edits[start:end] {
			switch e.kind {
			case keep:
				aCount, bCount = aCount+1, bCount+1
			case del:
				aCount++
			case add:
				bCount++
			}
		}
		if !emit(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount)) {
			break
		}
		for _, e := range edits[start:end] {
			if !emit(string(e.kind) + e.text + "\n") {
				break
			}
		}
		for _, e := range edits[start:end] {
			switch e.kind {
			case keep:
				aLine, bLine = aLine+1, bLine+1
			case del:
				aLine++
			case add:
				bLine++
			}
		}
		i = end
	}
	if !aNL || !bNL {
		emit("\\ No newline at end of file\n")
	}
	if truncated {
		out.WriteString("... diff truncated; review the whole file before approving\n")
		lines++
	}
	return out.String(), lines, truncated
}

// countKeepBefore returns the index of the first of up to n unchanged lines
// immediately before i.
func countKeepBefore(edits []edit, i, n int) int {
	j := i
	for j > 0 && i-j < n && edits[j-1].kind == keep {
		j--
	}
	return j
}

// splitLines splits text into lines and reports whether it ended with a
// newline, so the diff can say so the way diff(1) does.
func splitLines(text string) ([]string, bool) {
	if text == "" {
		return nil, true
	}
	endsNL := strings.HasSuffix(text, "\n")
	if endsNL {
		text = text[:len(text)-1]
	}
	return strings.Split(text, "\n"), endsNL
}

// diffLines returns the edit script from a to b. Common leading and trailing
// lines are matched directly, which is both exact and cheap for the usual
// "three lines changed in a config file"; the rest is compared with a longest
// common subsequence, or, when that would be too large, reported as one
// replacement.
func diffLines(a, b []string) []edit {
	var edits []edit
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		edits = append(edits, edit{keep, a[p]})
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	midA, midB := a[p:len(a)-s], b[p:len(b)-s]
	if len(midA)*len(midB) > maxDiffCells {
		for _, l := range midA {
			edits = append(edits, edit{del, l})
		}
		for _, l := range midB {
			edits = append(edits, edit{add, l})
		}
	} else {
		edits = append(edits, lcsEdits(midA, midB)...)
	}
	for i := len(a) - s; i < len(a); i++ {
		edits = append(edits, edit{keep, a[i]})
	}
	return edits
}

// lcsEdits is the classic dynamic-programming longest common subsequence,
// walked backwards into an edit script. Its table is bounded by maxDiffCells.
func lcsEdits(a, b []string) []edit {
	if len(a) == 0 || len(b) == 0 {
		out := make([]edit, 0, len(a)+len(b))
		for _, l := range a {
			out = append(out, edit{del, l})
		}
		for _, l := range b {
			out = append(out, edit{add, l})
		}
		return out
	}
	w := len(b) + 1
	table := make([]int32, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i*w+j] = table[(i+1)*w+j+1] + 1
			} else {
				table[i*w+j] = max(table[(i+1)*w+j], table[i*w+j+1])
			}
		}
	}
	var out []edit
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, edit{keep, a[i]})
			i, j = i+1, j+1
		case table[(i+1)*w+j] >= table[i*w+j+1]:
			out = append(out, edit{del, a[i]})
			i++
		default:
			out = append(out, edit{add, b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, edit{del, a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, edit{add, b[j]})
	}
	return out
}
