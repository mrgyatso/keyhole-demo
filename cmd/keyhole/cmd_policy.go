package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/mrgyatso/keyhole/internal/model"
)

// policyOSes are the Allow keys the agent understands, in display order.
var policyOSes = []string{"windows", "linux", "darwin"}

func cmdPolicyShow(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print the policy document, ready for policy set")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	p, err := ac.GetPolicy(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.out, p)
	}
	fmt.Fprintf(a.out, "Policy for %s, version %d\n\n", a.st.bold(slug), p.Version)
	t := newTable(a.out, "os", "rule", "path", "files")
	for _, goos := range policyKeys(p) {
		for _, r := range p.Allow[goos] {
			t.row(goos, r.ID, r.Path, strings.Join(r.Files, " "))
		}
	}
	t.flush()
	fmt.Fprintln(a.out)
	redact := a.st.green("on")
	if !p.Redact {
		redact = a.st.red("OFF")
	}
	kv(a.out,
		[2]string{"one read", humanBytes(p.MaxReadBytes)},
		[2]string{"largest file for grep/hash", humanBytes(p.MaxFileBytes)},
		[2]string{"list entries", fmt.Sprint(p.MaxListEntries)},
		[2]string{"grep matches", fmt.Sprint(p.MaxMatches)},
		[2]string{"per-session budget", humanBytes(p.SessionBudgetBytes)},
		[2]string{"secret redaction", redact},
	)
	fmt.Fprintln(a.out, "\n"+a.st.dim("The agent's compiled-in hard-deny list beats every rule above. Edit with: keyhole policy edit "+slug))
	return nil
}

func cmdPolicySet(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	file := fs.String("file", "", "policy JSON file, or - for stdin (required)")
	asJSON := fs.Bool("json", false, "print the stored policy as JSON")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	if *file == "" {
		return usagef("--file is required")
	}
	var b []byte
	if *file == "-" {
		b, err = io.ReadAll(a.in)
	} else {
		b, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	p, err := decodePolicy(b)
	if err == nil {
		err = validatePolicy(p)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", *file, err)
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	old, err := ac.GetPolicy(ctx, slug)
	if err != nil {
		return err
	}
	return a.storePolicy(ctx, ac, slug, old, p, *asJSON)
}

func cmdPolicyEdit(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	old, err := ac.GetPolicy(ctx, slug)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "keyhole-policy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, slug+"-policy.json")
	doc, err := json.MarshalIndent(old, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, append(doc, '\n'), 0o600); err != nil {
		return err
	}

	var p model.ClientPolicy
	for {
		if err := a.editFile(ctx, file); err != nil {
			return err
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		p, err = decodePolicy(b)
		if err == nil {
			err = validatePolicy(p)
		}
		if err == nil {
			break
		}
		fmt.Fprintf(a.errw, "%s the edited policy is invalid: %v\n", a.st.red("keyhole:"), err)
		if !a.interactive {
			return errAborted
		}
		fmt.Fprint(a.errw, "Edit again? [Y/n] ")
		line, _ := readLine(a.in)
		if s := strings.ToLower(strings.TrimSpace(line)); s == "n" || s == "no" {
			return errAborted
		}
	}
	p.Version = old.Version
	if samePolicy(old, p) {
		fmt.Fprintf(a.out, "No changes; the policy for %s stays at version %d.\n", slug, old.Version)
		return nil
	}
	return a.storePolicy(ctx, ac, slug, old, p, false)
}

// policyStore is the part of the admin client that storing a policy needs.
type policyStore interface {
	PutPolicy(ctx context.Context, slug string, p model.ClientPolicy) (model.ClientPolicy, error)
}

func (a *app) storePolicy(ctx context.Context, ac policyStore, slug string, old, p model.ClientPolicy, asJSON bool) error {
	stored, err := ac.PutPolicy(ctx, slug, p)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSON(a.out, stored)
	}
	fmt.Fprintf(a.out, "Policy for %s is now version %d.\n", a.st.bold(slug), stored.Version)
	changes := policyChanges(old, stored)
	if len(changes) == 0 {
		fmt.Fprintln(a.out, "  no changes to rules or caps")
	}
	for _, c := range changes {
		fmt.Fprintln(a.out, "  "+c)
	}
	return nil
}

// decodePolicy parses a policy document strictly: unknown fields, which
// are usually typos that would otherwise be dropped silently, are errors.
func decodePolicy(b []byte) (model.ClientPolicy, error) {
	var p model.ClientPolicy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("not a policy document: %w", err)
	}
	if dec.More() {
		return p, errors.New("not a policy document: trailing data after the JSON object")
	}
	return p, nil
}

var winAbs = regexp.MustCompile(`^[A-Za-z]:\\`)

// validatePolicy catches mistakes the relay or agent would otherwise reject
// later, or silently never match: unknown OS keys, missing or duplicate
// rule IDs, relative paths, bad globs and zero caps.
func validatePolicy(p model.ClientPolicy) error {
	var errs []error
	ids := map[string]string{}
	for goos, rules := range p.Allow {
		if !slices.Contains(policyOSes, goos) {
			errs = append(errs, fmt.Errorf("allow: unknown OS %q (want %s)", goos, strings.Join(policyOSes, ", ")))
			continue
		}
		for i, r := range rules {
			where := fmt.Sprintf("allow.%s[%d]", goos, i)
			if r.ID == "" {
				errs = append(errs, fmt.Errorf("%s: id is empty", where))
			} else if prev, dup := ids[r.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: id %q is already used by %s", where, r.ID, prev))
			} else {
				ids[r.ID] = where
			}
			sep := "/"
			switch {
			case goos == "windows" && !winAbs.MatchString(r.Path):
				errs = append(errs, fmt.Errorf("%s: path %q is not an absolute Windows path like C:\\Logs", where, r.Path))
			case goos != "windows" && !strings.HasPrefix(r.Path, "/"):
				errs = append(errs, fmt.Errorf("%s: path %q is not absolute", where, r.Path))
			}
			if goos == "windows" {
				sep = `\`
			}
			for _, seg := range strings.Split(r.Path, sep) {
				if _, err := path.Match(seg, ""); err != nil {
					errs = append(errs, fmt.Errorf("%s: path segment %q is not a valid glob", where, seg))
				}
			}
			for _, g := range r.Files {
				if _, err := path.Match(g, ""); err != nil || g == "" {
					errs = append(errs, fmt.Errorf("%s: files glob %q is not valid", where, g))
				}
			}
		}
	}
	for name, v := range map[string]int64{
		"max_read_bytes": p.MaxReadBytes, "max_file_bytes": p.MaxFileBytes, "max_list_entries": int64(p.MaxListEntries),
		"max_matches": int64(p.MaxMatches), "session_budget_bytes": p.SessionBudgetBytes,
	} {
		if v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be greater than zero", name))
		}
	}
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return errors.Join(errs...)
}

func samePolicy(a, b model.ClientPolicy) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// policyChanges describes what changed between two policies, one line
// each, so a widened scope is visible before anyone relies on it.
func policyChanges(old, new model.ClientPolicy) []string {
	var out []string
	keys := policyKeys(old)
	for _, k := range policyKeys(new) {
		if !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	for _, goos := range keys {
		before := map[string]string{}
		for _, r := range old.Allow[goos] {
			before[r.ID] = ruleString(r.Path, r.Files)
		}
		seen := map[string]bool{}
		for _, r := range new.Allow[goos] {
			seen[r.ID] = true
			now := ruleString(r.Path, r.Files)
			switch prev, ok := before[r.ID]; {
			case !ok:
				out = append(out, fmt.Sprintf("+ %s %s: %s", goos, r.ID, now))
			case prev != now:
				out = append(out, fmt.Sprintf("~ %s %s: %s -> %s", goos, r.ID, prev, now))
			}
		}
		for _, r := range old.Allow[goos] {
			if !seen[r.ID] {
				out = append(out, fmt.Sprintf("- %s %s: %s", goos, r.ID, before[r.ID]))
			}
		}
	}
	caps := []struct {
		name     string
		old, new string
	}{
		{"one read", humanBytes(old.MaxReadBytes), humanBytes(new.MaxReadBytes)},
		{"largest file", humanBytes(old.MaxFileBytes), humanBytes(new.MaxFileBytes)},
		{"list entries", fmt.Sprint(old.MaxListEntries), fmt.Sprint(new.MaxListEntries)},
		{"grep matches", fmt.Sprint(old.MaxMatches), fmt.Sprint(new.MaxMatches)},
		{"session budget", humanBytes(old.SessionBudgetBytes), humanBytes(new.SessionBudgetBytes)},
		{"redaction", onOff(old.Redact), onOff(new.Redact)},
	}
	for _, c := range caps {
		if c.old != c.new {
			out = append(out, fmt.Sprintf("~ %s: %s -> %s", c.name, c.old, c.new))
		}
	}
	return out
}

func ruleString(p string, files []string) string {
	if len(files) == 0 {
		return p
	}
	return p + " [" + strings.Join(files, " ") + "]"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "OFF"
}

// policyKeys returns the policy's OS keys: known ones first, in order.
func policyKeys(p model.ClientPolicy) []string {
	var keys []string
	for _, k := range policyOSes {
		if _, ok := p.Allow[k]; ok {
			keys = append(keys, k)
		}
	}
	var extra []string
	for k := range p.Allow {
		if !slices.Contains(policyOSes, k) {
			extra = append(extra, k)
		}
	}
	slices.Sort(extra)
	return append(keys, extra...)
}

// humanBytes renders a byte count in binary units: "2 MiB", "1.5 KiB".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	s := fmt.Sprintf("%.1f", v)
	s = strings.TrimSuffix(s, ".0")
	return s + " " + string("KMGTPE"[exp]) + "iB"
}
