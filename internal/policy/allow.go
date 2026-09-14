package policy

import (
	"path"
	"strings"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Decision is the policy verdict for one canonical path.
type Decision struct {
	DenyRule string          // hard-deny rule that refused the path; set only when refused by it
	Rule     proto.AllowRule // the allow rule that matched, when Allowed
	Root     string          // the concrete directory Rule's segments matched
	Allowed  bool
}

// Decide applies the whole policy to a canonical path: the hard-deny list
// first, then the allow rules. It is the one place that encodes "deny wins".
// The agent uses it on the requested path, again on the final path of every
// handle it opens, and to pick the entries a listing shows: directories
// unless hard-denied, anything else only if it also passes the Files filter
// of the rule that matches it.
func Decide(goos string, rules []proto.AllowRule, canonicalPath string, isDir bool) Decision {
	if id, denied := HardDenied(goos, canonicalPath); denied {
		return Decision{DenyRule: id}
	}
	rule, root, ok := MatchAllow(goos, rules, canonicalPath, isDir)
	return Decision{Rule: rule, Root: root, Allowed: ok}
}

// MatchAllow returns the first rule, in order, whose Path segments match the
// leading segments of canonicalPath and, unless isDir, whose Files filter
// (if any) matches the base name. root is the concrete directory the rule's
// segments matched, spelled with the path's own segments; the agent opens
// its os.Root there. Matching is segment-wise, never a string prefix, and
// case-insensitive on Windows and macOS. Rules that do not parse never
// match. MatchAllow ignores the hard-deny list; use Decide for a verdict.
func MatchAllow(goos string, rules []proto.AllowRule, canonicalPath string, isDir bool) (rule proto.AllowRule, root string, ok bool) {
	segs, reason := split(goos, canonicalPath)
	if reason != "" {
		return proto.AllowRule{}, "", false
	}
	keys := segs
	if foldsCase(goos) {
		keys = foldAll(segs)
	}
	for _, r := range rules {
		pat, ok := parseRule(goos, r.Path)
		if !ok || len(pat) > len(keys) || !matchSegments(pat, keys[:len(pat)]) {
			continue
		}
		if !isDir && len(r.Files) > 0 && (len(segs) == 0 || !filesMatch(goos, r.Files, segs[len(segs)-1])) {
			continue
		}
		return r, joinPath(goos, segs[:len(pat)]), true
	}
	return proto.AllowRule{}, "", false
}

// parseRule splits a rule path into folded glob segments. A rule that is not
// an absolute path in goos syntax, or has a malformed glob, does not parse.
func parseRule(goos, p string) ([]string, bool) {
	if goos == "windows" && strings.ContainsRune(p, '/') {
		return nil, false
	}
	segs, reason := split(goos, p)
	if reason != "" {
		return nil, false
	}
	for _, s := range segs {
		if _, err := path.Match(s, ""); err != nil {
			return nil, false
		}
	}
	if foldsCase(goos) {
		segs = foldAll(segs)
	}
	return segs, true
}

// SplitRule separates an allow rule's Path into its literal leading
// directory (every segment before the first glob) and the glob segments
// after it. The agent resolves symlinks in the literal part, so a rule for
// /var/log also matches the canonical /private/var/log on macOS. ok is false
// for a rule that does not parse.
func SplitRule(goos, rulePath string) (literal string, globs []string, ok bool) {
	if _, ok := parseRule(goos, rulePath); !ok {
		return "", nil, false
	}
	segs, _ := split(goos, rulePath)
	i := 0
	for i < len(segs) && !strings.ContainsAny(segs[i], `*?[\`) {
		i++
	}
	if goos == "windows" && i == 0 {
		return "", segs, true // a globbed drive has no literal part
	}
	if i == len(segs) {
		return joinPath(goos, segs), nil, true
	}
	return joinPath(goos, segs[:i]), segs[i:], true
}

func matchSegments(pat, segs []string) bool {
	for i := range pat {
		if !globMatch(pat[i], segs[i]) {
			return false
		}
	}
	return true
}

// filesMatch reports whether name passes a Files filter. A malformed glob
// matches nothing.
func filesMatch(goos string, globs []string, name string) bool {
	for _, g := range globs {
		if ok, err := MatchName(goos, g, name); err == nil && ok {
			return true
		}
	}
	return false
}

func joinPath(goos string, segs []string) string {
	if goos == "windows" {
		if len(segs) == 1 {
			return segs[0] + `\`
		}
		return strings.Join(segs, `\`)
	}
	return "/" + strings.Join(segs, "/")
}

// Rel returns p relative to root, in goos syntax ("." when they are the
// same), and whether p is root or below it. The comparison is segment-wise
// and folds case on Windows and macOS.
func Rel(goos, root, p string) (string, bool) {
	rs, reason := split(goos, root)
	if reason != "" {
		return "", false
	}
	ps, reason := split(goos, p)
	if reason != "" || len(rs) > len(ps) {
		return "", false
	}
	for i := range rs {
		a, b := rs[i], ps[i]
		if foldsCase(goos) {
			a, b = fold(a), fold(b)
		}
		if a != b {
			return "", false
		}
	}
	if len(rs) == len(ps) {
		return ".", true
	}
	return strings.Join(ps[len(rs):], separator(goos)), true
}
