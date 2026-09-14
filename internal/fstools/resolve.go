package fstools

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mrgyatso/keyhole/internal/policy"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// target is an opened, policy-checked filesystem object.
type target struct {
	root     *os.Root
	rootPath string // final path of the root directory
	rel      string // the object's path relative to root
	path     string // final path of the open handle
	rule     proto.AllowRule
	file     *os.File
	info     fs.FileInfo // from the open handle
}

func (t *target) close() {
	if t.file != nil {
		t.file.Close()
	}
	if t.root != nil {
		t.root.Close()
	}
}

// open resolves p and opens it read-only. The order matters:
//
//  1. CheckPathShape, before touching disk;
//  2. the hard-deny list on the path as spelled;
//  3. canonicalisation (symlinks resolved), then shape, deny and allow
//     rules again on the canonical path;
//  4. an os.Root at the matched rule's directory, an Lstat that refuses
//     links, reparse points and anything but files and directories, and a
//     read-only open relative to the root;
//  5. deny, allow and root containment again on the final path of the
//     open handle, which catches a symlink swapped in after step 3,
//     junctions and short names.
func (c *call) open(p string) (*target, error) {
	if p == "" {
		return nil, failf(proto.ErrBadRequest, "path is required")
	}
	if err := policy.CheckPathShape(c.goos, p); err != nil {
		return nil, unsafeShape(err)
	}
	if id, denied := policy.HardDenied(c.goos, p); denied {
		return nil, c.hardDenied(p, id)
	}
	rules := c.allowRules()
	canon, err := canonicalize(p)
	if err != nil {
		if !c.lexicallyAllowed(p) {
			return nil, notAllowed(p)
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, failf(proto.ErrUnsafePath, "%s goes through a symbolic link loop", p)
		}
		return nil, failf(proto.ErrIO, "cannot resolve %s: %v", p, err)
	}
	if err := policy.CheckPathShape(c.goos, canon); err != nil {
		return nil, failf(proto.ErrUnsafePath, "%s resolves through a link to a path the agent will not open", p)
	}
	d := policy.Decide(c.goos, rules, canon, false)
	if d.DenyRule != "" {
		return nil, c.hardDenied(p, d.DenyRule)
	}
	if !d.Allowed {
		d = policy.Decide(c.goos, rules, canon, true) // a directory, or a file the Files filter refuses
	}
	if !d.Allowed {
		if c.lexicallyAllowed(p) {
			return nil, failf(proto.ErrUnsafePath, "%s resolves through a link to a path outside its allow rule", p)
		}
		return nil, notAllowed(p)
	}
	c.meta.RuleID = d.Rule.ID
	rel, ok := policy.Rel(c.goos, d.Root, canon)
	if !ok {
		return nil, failf(proto.ErrInternal, "allow rule root %s does not contain %s", d.Root, canon)
	}
	t := &target{rel: rel, rule: d.Rule}
	if err := c.openIn(t, d.Root, p); err != nil {
		t.close()
		return nil, err
	}
	return t, nil
}

// openIn opens t.rel beneath root and verifies the handle.
func (c *call) openIn(t *target, root, p string) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		if fi, serr := os.Stat(root); serr == nil && !fi.IsDir() {
			return failf(proto.ErrNotAllowed, "allow rule %s names a file; rules name directories and pick files with Files", t.rule.ID)
		}
		return openError(p, err)
	}
	t.root = r
	if t.rootPath, err = rootFinalPath(r); err != nil {
		return failf(proto.ErrIO, "cannot verify the allow rule's directory: %v", err)
	}
	li, err := r.Lstat(t.rel)
	if err != nil {
		return openError(p, err)
	}
	if isLink(li) {
		return failf(proto.ErrUnsafePath, "%s is a symbolic link, junction or other reparse point", p)
	}
	if !li.IsDir() && !li.Mode().IsRegular() {
		return failf(proto.ErrNotRegular, "%s is not a regular file or directory", p)
	}
	f, err := r.OpenFile(t.rel, openFlags, 0)
	if err != nil {
		return openError(p, err)
	}
	t.file = f
	if t.info, err = f.Stat(); err != nil {
		return failf(proto.ErrIO, "stat %s: %v", p, err)
	}
	if reparse, err := handleIsReparse(f); err != nil || reparse {
		return failf(proto.ErrUnsafePath, "%s is a reparse point", p)
	}
	if !t.info.IsDir() && !t.info.Mode().IsRegular() {
		return failf(proto.ErrNotRegular, "%s is not a regular file or directory", p)
	}
	if t.path, err = finalPath(f); err != nil {
		return failf(proto.ErrIO, "cannot verify the opened path of %s: %v", p, err)
	}
	c.meta.ResolvedPath = t.path
	return c.checkFinal(t, p)
}

// checkFinal re-applies the policy to the final path of an open handle.
func (c *call) checkFinal(t *target, p string) error {
	if err := policy.CheckPathShape(c.goos, t.path); err != nil {
		return failf(proto.ErrUnsafePath, "%s opened as a path the agent will not read", p)
	}
	if _, ok := policy.Rel(c.goos, t.rootPath, t.path); !ok {
		return failf(proto.ErrUnsafePath, "%s resolved outside its allow rule's directory", p)
	}
	rules := c.allowRules()
	d := policy.Decide(c.goos, rules, t.path, t.info.IsDir())
	switch {
	case d.DenyRule != "":
		return c.hardDenied(p, d.DenyRule)
	case d.Allowed:
		t.rule = d.Rule
		c.meta.RuleID = d.Rule.ID
		return nil
	case !t.info.IsDir() && policy.Decide(c.goos, rules, t.path, true).Allowed:
		return failf(proto.ErrNotAllowed, "%s is not allowed: the allow rule only covers files named %s",
			p, strings.Join(t.rule.Files, ", "))
	default:
		return failf(proto.ErrUnsafePath, "%s resolved outside every allow rule (link, junction or reparse point)", p)
	}
}

func rootFinalPath(r *os.Root) (string, error) {
	d, err := r.Open(".")
	if err != nil {
		return "", err
	}
	defer d.Close()
	return finalPath(d)
}

// allowRules returns the policy's rules with symlinks resolved in each
// rule's literal leading directory, so rules match canonical paths: a rule
// for /var/log also covers /private/var/log on macOS.
func (c *call) allowRules() []proto.AllowRule {
	if c.rules == nil {
		c.rules = make([]proto.AllowRule, 0, len(c.pol.Allow))
		for _, r := range c.pol.Allow {
			c.rules = append(c.rules, canonicalRule(c.goos, r))
		}
	}
	return c.rules
}

func canonicalRule(goos string, r proto.AllowRule) proto.AllowRule {
	lit, globs, ok := policy.SplitRule(goos, r.Path)
	if !ok || lit == "" {
		return r
	}
	canon, err := canonicalize(lit)
	if err != nil {
		return r
	}
	sep := string(filepath.Separator)
	if len(globs) == 0 {
		r.Path = canon
	} else {
		r.Path = strings.TrimSuffix(canon, sep) + sep + strings.Join(globs, sep)
	}
	return r
}

// lexicallyAllowed reports whether p, as spelled, is inside an allow rule.
// It separates "outside your scope" (not_allowed) from "inside your scope
// but a link leads out" (unsafe_path) without revealing anything about
// paths outside every rule.
func (c *call) lexicallyAllowed(p string) bool {
	if _, _, ok := policy.MatchAllow(c.goos, c.pol.Allow, p, true); ok {
		return true
	}
	_, _, ok := policy.MatchAllow(c.goos, c.allowRules(), p, true)
	return ok
}

// canonicalize resolves symlinks in the longest existing prefix of p and
// appends the rest unchanged, so a missing file still gets a canonical
// spelling to check against the policy.
func canonicalize(p string) (string, error) {
	p = filepath.Clean(p)
	c, err := filepath.EvalSymlinks(p)
	if err == nil {
		return c, nil
	}
	if !isNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p, nil
	}
	cp, err := canonicalize(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(cp, filepath.Base(p)), nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

func openError(p string, err error) error {
	switch {
	case isNotExist(err):
		return failf(proto.ErrNotFound, "%s does not exist", p)
	case errors.Is(err, syscall.ELOOP), strings.Contains(err.Error(), "path escapes from parent"):
		return failf(proto.ErrUnsafePath, "%s leads outside its allow rule's directory through a link", p)
	case errors.Is(err, fs.ErrPermission):
		return failf(proto.ErrIO, "%s: permission denied by the operating system", p)
	default:
		return failf(proto.ErrIO, "%s: %v", p, err)
	}
}

func unsafeShape(err error) error {
	var pe *policy.UnsafePathError
	if errors.As(err, &pe) {
		return failf(proto.ErrUnsafePath, "%s: %s", pe.Path, pe.Reason)
	}
	return failf(proto.ErrUnsafePath, "%v", err)
}

func notAllowed(p string) error {
	return failf(proto.ErrNotAllowed, "%s is outside every allow rule for this device", p)
}

func (c *call) hardDenied(p, ruleID string) error {
	c.meta.RuleID = ruleID
	return failf(proto.ErrHardDenied, "%s is or resolves to a path on the agent's hard-deny list (%s); it can never be read", p, ruleID)
}
