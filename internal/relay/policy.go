package relay

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/mrgyatso/keyhole/internal/model"
	"github.com/mrgyatso/keyhole/internal/natsauth"
)

// Upper bounds on a client policy's caps. They keep one response under the
// NATS max_payload: a read can double when JSON-escaped, and list entries
// and grep lines add up.
const (
	maxReadBytesCap   = natsauth.MaxPayload / 4
	maxFileBytesCap   = 4 << 30
	maxListEntriesCap = 10000
	maxMatchesCap     = 2000
	maxSessionBudget  = 4 << 30
)

// validatePolicy checks a client policy before it is stored: every rule has
// a unique ID and an absolute path in its OS's syntax whose segments are
// valid globs, every Files entry is a valid base-name glob, and the caps are
// positive and bounded. The agent still enforces path safety and the
// hard-deny list; this only refuses policies that cannot mean anything.
func validatePolicy(p model.ClientPolicy) error {
	for goos, rules := range p.Allow {
		if !supportedOS[goos] {
			return fmt.Errorf("allow: unknown os %q (want windows, linux or darwin)", goos)
		}
		ids := map[string]bool{}
		for i, r := range rules {
			where := fmt.Sprintf("allow.%s[%d]", goos, i)
			if strings.TrimSpace(r.ID) == "" {
				return fmt.Errorf("%s: rule has no id", where)
			}
			if ids[r.ID] {
				return fmt.Errorf("%s: duplicate rule id %q", where, r.ID)
			}
			ids[r.ID] = true
			if err := validateRulePath(goos, r.Path); err != nil {
				return fmt.Errorf("%s (%s): path %q: %w", where, r.ID, r.Path, err)
			}
			for _, f := range r.Files {
				if err := validateGlob(f); err != nil {
					return fmt.Errorf("%s (%s): files glob %q: %w", where, r.ID, f, err)
				}
			}
		}
	}
	caps := []struct {
		name     string
		val, max int64
	}{
		{"max_read_bytes", p.MaxReadBytes, maxReadBytesCap},
		{"max_file_bytes", p.MaxFileBytes, maxFileBytesCap},
		{"max_list_entries", int64(p.MaxListEntries), maxListEntriesCap},
		{"max_matches", int64(p.MaxMatches), maxMatchesCap},
		{"session_budget_bytes", p.SessionBudgetBytes, maxSessionBudget},
	}
	for _, c := range caps {
		if c.val < 1 || c.val > c.max {
			return fmt.Errorf("%s must be between 1 and %d", c.name, c.max)
		}
	}
	return nil
}

// validateRulePath checks that p is absolute in goos's syntax: a drive-letter
// path with backslashes on Windows (no UNC, device or \\?\ forms), a
// slash-rooted path elsewhere, with no empty, "." or ".." segments.
func validateRulePath(goos, p string) error {
	var rest, sep string
	switch goos {
	case "windows":
		if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || p[2] != '\\' {
			return errors.New(`must be an absolute path like C:\Windows\Logs`)
		}
		if strings.Contains(p, "/") {
			return errors.New("must use backslashes")
		}
		rest, sep = p[3:], `\`
	default:
		if !strings.HasPrefix(p, "/") {
			return errors.New("must be an absolute path like /var/log")
		}
		rest, sep = p[1:], "/"
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("contains control characters")
	}
	if rest == "" {
		return nil // a drive or filesystem root; the hard-deny list still applies
	}
	for seg := range strings.SplitSeq(rest, sep) {
		switch {
		case seg == "":
			return errors.New("has an empty segment")
		case seg == "." || seg == "..":
			return errors.New(`has a "." or ".." segment`)
		case goos == "windows" && strings.ContainsAny(seg, `:<>"|`):
			return fmt.Errorf("segment %q has a character Windows forbids", seg)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("segment %q is not a valid glob", seg)
		}
	}
	return nil
}

// validateGlob checks a Files entry: a non-empty base-name glob.
func validateGlob(g string) error {
	if g == "" {
		return errors.New("is empty")
	}
	if strings.ContainsAny(g, `/\`) {
		return errors.New("must match a base name, without separators")
	}
	if _, err := path.Match(g, ""); err != nil {
		return errors.New("is not a valid glob")
	}
	return nil
}

func isASCIILetter(b byte) bool { return (b|0x20) >= 'a' && (b|0x20) <= 'z' }
