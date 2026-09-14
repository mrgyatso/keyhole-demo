package redact

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Windowed scanning, and why it finds what a whole-text scan finds.
//
// A rule is windowable when its pattern proves three things:
//
//  1. every match contains one of the rule's own keywords;
//  2. nothing in the pattern before that keyword can match a newline, so a
//     match starts on its keyword's line;
//  3. after the keyword, the pattern can cross only a bounded number of
//     newlines. The pattern's final node is exempt if a newline can only be
//     the last character it matches (the usual (?:[\s;]|$) terminator), since
//     that adds nothing from the next line.
//
// Then every match lies inside its keyword's line plus the next reach.lines
// lines, and when the pattern bounds the bytes between the keyword and its
// last interior newline, inside the lines that start within reach.bytes
// after the keyword's line. A rule's windows are built around every
// occurrence of each of its keywords, so they contain all of its matches.
// Rules that fail the proof scan the whole text.

// unbounded stands for "no finite bound" in maxNL and maxLen.
const unbounded = 1 << 30

// maxFinite caps the finite-language expansion used to find keywords.
const maxFinite = 256

// reach bounds how far a match extends past the end of its keyword's line.
type reach struct {
	lines int // newlines a match can cross after its keyword
	bytes int // bytes from the keyword to the last interior newline; unbounded if not bounded
}

// analyze reports whether pattern is windowable for keywords, and its reach.
func analyze(pattern string, keywords []string) (reach, bool) {
	if len(keywords) == 0 {
		return reach{}, false
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return reach{}, false
	}
	return analyzeNode(re, lowerAll(keywords))
}

func analyzeNode(re *syntax.Regexp, kws []string) (reach, bool) {
	switch re.Op {
	case syntax.OpCapture:
		return analyzeNode(re.Sub[0], kws)
	case syntax.OpConcat:
		return analyzeSeq(re.Sub, kws)
	case syntax.OpAlternate:
		var out reach
		for _, b := range re.Sub {
			r, ok := analyzeNode(b, kws)
			if !ok {
				return analyzeSeq([]*syntax.Regexp{re}, kws)
			}
			out.lines, out.bytes = max(out.lines, r.lines), max(out.bytes, r.bytes)
		}
		return out, true
	}
	return analyzeSeq([]*syntax.Regexp{re}, kws)
}

func analyzeSeq(seq []*syntax.Regexp, kws []string) (reach, bool) {
	// regexp/syntax can factor a common prefix out of an alternation whose
	// branches each contain the keyword. Analyze that alternation as a unit;
	// a flat finite-language proof cannot handle a branch with bounded \s.
	for i, n := range seq {
		target := n
		for target.Op == syntax.OpCapture {
			target = target.Sub[0]
		}
		if len(seq) > 1 && target.Op == syntax.OpAlternate {
			if nested, ok := analyzeNode(target, kws); ok {
				return addSuffixReach(nested, seq[i+1:])
			}
		}
		if maxNL(n) > 0 {
			break
		}
	}
	k, ok := keywordEnd(seq, kws)
	if !ok {
		return reach{}, false
	}
	after := seq[k+1:]
	interior := after
	if n := len(after); n > 0 && endsOnly(after[n-1]) {
		interior = after[:n-1]
	}
	var r reach
	last := -1
	for i, n := range interior {
		c := maxNL(n)
		if c >= unbounded {
			return reach{}, false
		}
		if c > 0 {
			r.lines, last = sat(r.lines+c), i
		}
	}
	for _, n := range interior[:last+1] {
		r.bytes = sat(r.bytes + maxLen(n))
	}
	return r, true
}

func addSuffixReach(r reach, after []*syntax.Regexp) (reach, bool) {
	interior := after
	if n := len(after); n > 0 && endsOnly(after[n-1]) {
		interior = after[:n-1]
	}
	last := -1
	for i, n := range interior {
		c := maxNL(n)
		if c >= unbounded {
			return reach{}, false
		}
		if c > 0 {
			r.lines, last = sat(r.lines+c), i
		}
	}
	if last >= 0 {
		for _, n := range interior[:last+1] {
			r.bytes = sat(r.bytes + maxLen(n))
		}
	}
	return r, r.bytes < unbounded
}

// keywordEnd finds the first node of seq, or run of consecutive nodes with
// a finite language, whose every match contains a keyword, and returns the
// index of its last node. Every node up to there must be unable to match a
// newline.
func keywordEnd(seq []*syntax.Regexp, kws []string) (int, bool) {
	for i := range seq {
		if maxNL(seq[i]) > 0 {
			return 0, false
		}
		if j, ok := runWithKeyword(seq, i, kws); ok {
			return j, true
		}
	}
	return 0, false
}

// runWithKeyword checks seq[i] alone, then seq[i], seq[i+1], … as long as
// their languages are finite and newline-free, for a guaranteed keyword.
// Parsing factors alternations (password|pwd becomes p(?:assword|wd)), so a
// keyword is often spread over several nodes.
func runWithKeyword(seq []*syntax.Regexp, i int, kws []string) (int, bool) {
	if hasKeyword(seq[i], kws) {
		return i, true
	}
	strs := []string{""}
	for j := i; j < len(seq) && maxNL(seq[j]) == 0; j++ {
		ss, ok := finiteStrings(seq[j])
		if !ok {
			break
		}
		if strs, ok = product(strs, ss); !ok {
			break
		}
		if allContain(strs, kws) {
			return j, true
		}
	}
	return 0, false
}

// hasKeyword reports whether every match of re contains one of kws.
func hasKeyword(re *syntax.Regexp, kws []string) bool {
	if ss, ok := finiteStrings(re); ok {
		return allContain(ss, kws)
	}
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return hasKeyword(re.Sub[0], kws)
	case syntax.OpRepeat:
		return re.Min >= 1 && hasKeyword(re.Sub[0], kws)
	case syntax.OpAlternate:
		for _, b := range re.Sub {
			if !hasKeyword(b, kws) {
				return false
			}
		}
		return true
	case syntax.OpConcat:
		for i := range re.Sub {
			if _, ok := runWithKeyword(re.Sub, i, kws); ok {
				return true
			}
		}
	}
	return false
}

// finiteStrings returns the lower-cased strings re can match, if they are
// few (up to maxFinite).
func finiteStrings(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}, true
	case syntax.OpCharClass:
		n := 0
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if n += int(re.Rune[i+1]-re.Rune[i]) + 1; n > maxFinite {
				return nil, false
			}
		}
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for c := re.Rune[i]; c <= re.Rune[i+1]; c++ {
				out = append(out, strings.ToLower(string(c)))
			}
		}
		return dedupe(out), true
	case syntax.OpCapture:
		return finiteStrings(re.Sub[0])
	case syntax.OpQuest:
		ss, ok := finiteStrings(re.Sub[0])
		return append(ss, ""), ok
	case syntax.OpConcat:
		strs := []string{""}
		for _, s := range re.Sub {
			ss, ok := finiteStrings(s)
			if !ok {
				return nil, false
			}
			if strs, ok = product(strs, ss); !ok {
				return nil, false
			}
		}
		return strs, true
	case syntax.OpAlternate:
		var out []string
		for _, b := range re.Sub {
			ss, ok := finiteStrings(b)
			if !ok || len(out)+len(ss) > maxFinite {
				return nil, false
			}
			out = append(out, ss...)
		}
		return dedupe(out), true
	case syntax.OpRepeat:
		if re.Max < 0 || re.Max > 4 {
			return nil, false
		}
		ss, ok := finiteStrings(re.Sub[0])
		if !ok {
			return nil, false
		}
		var out []string
		cur := []string{""}
		for n := 0; n <= re.Max; n++ {
			if n >= re.Min {
				out = append(out, cur...)
			}
			if cur, ok = product(cur, ss); !ok || len(out) > maxFinite {
				return nil, false
			}
		}
		return dedupe(out), true
	}
	return nil, false
}

// endsOnly reports whether a newline matched by re can only be the last
// character of its match.
func endsOnly(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary,
		syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return true
	case syntax.OpCapture, syntax.OpQuest:
		return endsOnly(re.Sub[0])
	case syntax.OpLiteral:
		for _, c := range re.Rune[:max(len(re.Rune)-1, 0)] {
			if c == '\n' {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, b := range re.Sub {
			if !endsOnly(b) {
				return false
			}
		}
		return true
	case syntax.OpConcat:
		n := len(re.Sub)
		for _, s := range re.Sub[:n-1] {
			if maxNL(s) > 0 {
				return false
			}
		}
		return endsOnly(re.Sub[n-1])
	}
	return false
}

// maxNL is the most newlines a match of re can contain.
func maxNL(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, c := range re.Rune {
			if c == '\n' {
				n++
			}
		}
		return n
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				return 1
			}
		}
		return 0
	case syntax.OpAnyChar:
		return 1
	case syntax.OpCapture, syntax.OpQuest:
		return maxNL(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if maxNL(re.Sub[0]) > 0 {
			return unbounded
		}
		return 0
	case syntax.OpRepeat:
		n := maxNL(re.Sub[0])
		switch {
		case n == 0:
			return 0
		case re.Max < 0:
			return unbounded
		}
		return sat(n * re.Max)
	case syntax.OpConcat:
		t := 0
		for _, s := range re.Sub {
			t = sat(t + maxNL(s))
		}
		return t
	case syntax.OpAlternate:
		m := 0
		for _, s := range re.Sub {
			m = max(m, maxNL(s))
		}
		return m
	}
	return 0
}

// maxLen is the most bytes a match of re can span.
func maxLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				n += foldLen(c)
			} else {
				n += runeLen(c)
			}
		}
		return n
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0
		}
		return runeLen(re.Rune[len(re.Rune)-1])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax
	case syntax.OpCapture, syntax.OpQuest:
		return maxLen(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if maxLen(re.Sub[0]) == 0 {
			return 0
		}
		return unbounded
	case syntax.OpRepeat:
		n := maxLen(re.Sub[0])
		switch {
		case n == 0:
			return 0
		case re.Max < 0:
			return unbounded
		}
		return sat(n * re.Max)
	case syntax.OpConcat:
		t := 0
		for _, s := range re.Sub {
			t = sat(t + maxLen(s))
		}
		return t
	case syntax.OpAlternate:
		m := 0
		for _, s := range re.Sub {
			m = max(m, maxLen(s))
		}
		return m
	}
	return 0
}

// foldLen is the longest UTF-8 encoding among c's case-fold partners
// (k also matches the 3-byte Kelvin sign under (?i)).
func foldLen(c rune) int {
	n := runeLen(c)
	for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
		n = max(n, runeLen(f))
	}
	return n
}

func runeLen(c rune) int {
	if n := utf8.RuneLen(c); n > 0 {
		return n
	}
	return utf8.UTFMax
}

func sat(n int) int { return min(n, unbounded) }

func product(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxFinite {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out, true
}

func allContain(ss, kws []string) bool {
	if len(ss) == 0 {
		return false
	}
	for _, s := range ss {
		found := false
		for _, k := range kws {
			if strings.Contains(s, k) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func dedupe(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func lowerAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
