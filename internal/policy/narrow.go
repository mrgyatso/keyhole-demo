package policy

import (
	"slices"
	"strings"

	"github.com/mrgyatso/keyhole/internal/proto"
)

// Narrow returns the part of an allow-rule list that lies within roots. It is
// how the endpoint applies a grant it approved on a technician's unlock:
// nobody at the machine looked at that grant's paths, so they may only select
// from what the client's policy already allows, never add to it.
//
// For each rule, in order:
//
//   - a rule that lies within a root is kept whole, with its ID and Files;
//   - otherwise each root that lies within the rule becomes a rule of its own,
//     with the rule's ID and Files filter;
//   - a rule that only partly overlaps a root contributes nothing.
//
// Every rule returned therefore matches only paths that both the policy and
// the roots match. Keeping the rules' order keeps "first matching rule wins",
// so a Files filter still picks the files it picked in the policy.
//
// Containment is decided segment by segment, folding case where goos does,
// exactly as MatchAllow matches. A glob segment is known to contain a literal
// segment it matches and a glob identical to it; any other pair of globs
// counts as not contained, which can only drop access. Rules and roots that
// do not parse contribute nothing.
func Narrow(goos string, rules []proto.AllowRule, roots []string) []proto.AllowRule {
	type root struct {
		path string
		segs []string
	}
	parsed := make([]root, 0, len(roots))
	for _, p := range roots {
		if segs, ok := parseRule(goos, p); ok {
			parsed = append(parsed, root{path: p, segs: segs})
		}
	}
	var out []proto.AllowRule
	for _, r := range rules {
		pat, ok := parseRule(goos, r.Path)
		if !ok {
			continue
		}
		// A rule kept whole already covers every narrower copy of itself.
		if slices.ContainsFunc(parsed, func(g root) bool { return within(pat, g.segs) }) {
			out = append(out, proto.AllowRule{ID: r.ID, Path: r.Path, Files: slices.Clone(r.Files)})
			continue
		}
		for _, g := range parsed {
			if within(g.segs, pat) {
				out = append(out, proto.AllowRule{ID: r.ID, Path: g.path, Files: slices.Clone(r.Files)})
			}
		}
	}
	return out
}

// within reports whether every path the parsed pattern inner covers is also
// covered by outer: inner is at least as deep, and each of outer's segments
// contains inner's segment at the same depth.
func within(inner, outer []string) bool {
	if len(inner) < len(outer) {
		return false
	}
	for i, o := range outer {
		if !segmentWithin(inner[i], o) {
			return false
		}
	}
	return true
}

// segmentWithin reports whether every name the segment pattern inner matches
// is also matched by outer. Both are already folded where the OS folds case.
func segmentWithin(inner, outer string) bool {
	switch {
	case inner == outer:
		return true
	case hasGlob(inner):
		// Whether one glob contains another is not worth deciding here: the
		// answer "no" is always safe, because it can only drop access.
		return false
	}
	return globMatch(outer, inner)
}

// hasGlob reports whether a segment is a pattern rather than a literal name,
// by the same test globMatch uses.
func hasGlob(s string) bool { return strings.ContainsAny(s, `*?[\`) }
