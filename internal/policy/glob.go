package policy

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// foldsCase reports whether goos compares names case-insensitively: Windows
// (NTFS) and macOS (APFS and HFS+ are case-insensitive by default).
func foldsCase(goos string) bool { return goos == "windows" || goos == "darwin" }

// fold maps s to a case-folded key. It errs towards folding more than the
// filesystem does, never less: each rune is upper-cased and then replaced by
// the smallest rune in its Unicode folding orbit, so "ſ" and "s", the Kelvin
// sign and "k", and the dotless "ı" and "i" all compare equal.
func fold(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || ('a' <= c && c <= 'z') {
			return strings.Map(foldRune, s)
		}
	}
	return s
}

func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}
	r = unicode.ToUpper(r)
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		m = min(m, f)
	}
	return m
}

func foldAll(segs []string) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = fold(s)
	}
	return out
}

// globMatch matches one segment against a path.Match pattern. Both are
// already folded where the OS folds case.
func globMatch(pattern, name string) bool {
	if !strings.ContainsAny(pattern, `*?[\`) {
		return pattern == name
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

// matchPrefix reports whether the deny pattern pat matches a leading run of
// segs. A "**" segment matches any number of segments, including none. Allow
// rules do not use it: their segments each match exactly one path segment.
func matchPrefix(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			for i := 0; i <= len(segs); i++ {
				if matchPrefix(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 || !globMatch(pat[0], segs[0]) {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return true
}

// MatchName reports whether a base name matches a path.Match glob, folding
// case where goos does. A malformed pattern is an error.
func MatchName(goos, pattern, name string) (bool, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return false, err
	}
	if foldsCase(goos) {
		pattern, name = fold(pattern), fold(name)
	}
	return globMatch(pattern, name), nil
}
