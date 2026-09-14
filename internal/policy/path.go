package policy

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Path handling here is pure string logic, parameterised by the device's
// GOOS, so Windows rules are testable on any host. Windows paths are
// "X:\seg\seg" with backslashes only; every other GOOS uses "/seg/seg".

// UnsafePathError reports a path refused on its shape alone, before any
// filesystem access. The agent answers it with proto.ErrUnsafePath.
type UnsafePathError struct {
	Path   string
	Reason string
}

func (e *UnsafePathError) Error() string {
	return "unsafe path " + strconv.Quote(e.Path) + ": " + e.Reason
}

func unsafePath(p, reason string) error { return &UnsafePathError{Path: p, Reason: reason} }

// CheckPathShape rejects paths that could name something other than the
// plain file they appear to: relative paths, "." and ".." segments, empty
// segments, control characters and invalid UTF-8 everywhere, and on Windows
// also device and namespace prefixes (\\?\, \\.\), UNC paths, forward
// slashes, alternate data streams, reserved device names, 8.3 short names,
// wildcard characters and segments ending in a dot or a space. One trailing
// separator is accepted.
func CheckPathShape(goos, p string) error {
	if !utf8.ValidString(p) {
		return unsafePath(p, "not valid UTF-8")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return unsafePath(p, "contains a control character")
		}
	}
	if goos == "windows" {
		switch {
		case strings.HasPrefix(p, `\\`), strings.HasPrefix(p, `//`):
			return unsafePath(p, `device, namespace (\\?\, \\.\) and UNC paths are not allowed; use a drive path like C:\...`)
		case strings.ContainsRune(p, '/'):
			return unsafePath(p, "forward slashes are not allowed in Windows paths; use backslashes")
		}
	}
	segs, reason := split(goos, p)
	if reason != "" {
		return unsafePath(p, reason)
	}
	if goos == "windows" {
		for _, s := range segs[1:] {
			if reason := windowsSegmentProblem(s); reason != "" {
				return unsafePath(p, reason)
			}
		}
	}
	return nil
}

func separator(goos string) string {
	if goos == "windows" {
		return `\`
	}
	return "/"
}

// split parses an absolute path into its segments; on Windows the first
// segment is the drive ("C:"). It checks syntax only (no per-segment
// Windows rules), so it also parses allow-rule globs and deny patterns. The
// second result is the reason p does not parse.
func split(goos, p string) ([]string, string) {
	var segs []string
	var rest string
	if goos == "windows" {
		if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || p[2] != '\\' {
			return nil, `not an absolute path of the form C:\...`
		}
		segs, rest = []string{p[:2]}, p[3:]
	} else {
		if !strings.HasPrefix(p, "/") {
			return nil, "not an absolute path"
		}
		rest = p[1:]
	}
	sep := separator(goos)
	if strings.HasPrefix(rest, sep) {
		return nil, "empty path segment"
	}
	rest = strings.TrimSuffix(rest, sep)
	if rest == "" {
		return segs, ""
	}
	for _, s := range strings.Split(rest, sep) {
		switch s {
		case "":
			return nil, "empty path segment"
		case ".", "..":
			return nil, `"." and ".." segments are not allowed`
		}
		segs = append(segs, s)
	}
	return segs, ""
}

// windowsSegmentProblem returns why one Windows path segment (not the drive)
// is unsafe, or "".
func windowsSegmentProblem(s string) string {
	switch {
	case strings.ContainsRune(s, ':'):
		return `alternate data streams (":" after the drive letter) are not allowed`
	case strings.ContainsAny(s, `<>"|?*`):
		return `contains a character Windows does not allow in names (<>"|?*)`
	case strings.HasSuffix(s, "."), strings.HasSuffix(s, " "):
		return "a segment ends in a dot or a space, which Windows strips"
	case isReservedDeviceName(s):
		return "reserved device name (CON, NUL, COM1, ...)"
	case isShortName(s):
		return "8.3 short-name segment (like PROGRA~1); use the long name"
	}
	return ""
}

// isReservedDeviceName reports whether s names a DOS device: CON, PRN, AUX,
// NUL, COM0-9, LPT0-9 (and the superscript-digit forms), CONIN$ or CONOUT$,
// in any case, with or without an extension and trailing spaces.
func isReservedDeviceName(s string) bool {
	base, _, _ := strings.Cut(s, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if !strings.HasPrefix(base, "COM") && !strings.HasPrefix(base, "LPT") {
		return false
	}
	switch base[3:] {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
		return true
	}
	return false
}

// isShortName reports whether s could be an 8.3 alias such as PROGRA~1: a
// "~" followed by a digit, in a name no longer than 8.3 allows.
func isShortName(s string) bool {
	if utf8.RuneCountInString(s) > 12 {
		return false
	}
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '~' && s[i+1] >= '0' && s[i+1] <= '9' {
			return true
		}
	}
	return false
}

func isASCIILetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
