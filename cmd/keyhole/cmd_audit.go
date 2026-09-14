package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminclient"
)

func cmdAuditReport(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	fromS := fs.String("from", "", "start, inclusive: RFC 3339, YYYY-MM-DD (local midnight), or an age like 7d or 24h")
	toS := fs.String("to", "", "end, exclusive: same forms as --from")
	format := fs.String("format", adminclient.FormatCSV, "csv, jsonl or pdf")
	out := fs.String("o", "", "write to FILE instead of stdout (required for pdf)")
	fs.StringVar(out, "output", "", "same as -o")
	pos, err := exactArgs(fs, args, "<slug>")
	if err != nil {
		return err
	}
	slug, err := slugArg(pos[0])
	if err != nil {
		return err
	}
	switch *format {
	case adminclient.FormatCSV, adminclient.FormatJSONL, adminclient.FormatPDF:
	default:
		return usagef("--format must be csv, jsonl or pdf")
	}
	if *format == adminclient.FormatPDF && *out == "" {
		return usagef("--format pdf writes a binary file; add -o FILE, for example -o %s-audit.pdf", slug)
	}
	now := a.now()
	from, err := parseWhen(*fromS, now)
	if err != nil {
		return usagef("--from: %v", err)
	}
	to, err := parseWhen(*toS, now)
	if err != nil {
		return usagef("--to: %v", err)
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return usagef("--from must be before --to")
	}
	ac, _, err := a.admin()
	if err != nil {
		return err
	}
	q := adminclient.AuditQuery{From: from, To: to, Format: *format}
	if *out == "" {
		_, err := ac.AuditExport(ctx, slug, q, a.out)
		return err
	}
	n, err := exportToFile(ctx, ac, slug, q, *out)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.errw, "Wrote the %s audit report for %s (%s) to %s, %s.\n", *format, slug, describeRange(from, to), *out, humanBytes(n))
	return nil
}

// exportToFile streams the export into a private temporary file beside
// path and renames it into place only when the stream completed, so a
// failed export never leaves a partial report behind.
func exportToFile(ctx context.Context, ac *adminclient.Client, slug string, q adminclient.AuditQuery, path string) (int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyhole-audit-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return 0, err
	}
	n, err := ac.AuditExport(ctx, slug, q, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	return n, os.Rename(tmp.Name(), path)
}

// parseWhen accepts RFC 3339, a local date (YYYY-MM-DD) or date and minute
// (YYYY-MM-DDTHH:MM), or an age counted back from now: a Go duration like
// 36h, or whole days like 7d. "" is an open bound.
func parseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("%q is not a time: use RFC 3339, YYYY-MM-DD, or an age like 7d or 24h", s)
}

func describeRange(from, to time.Time) string {
	switch {
	case from.IsZero() && to.IsZero():
		return "all entries"
	case to.IsZero():
		return "from " + stamp(from)
	case from.IsZero():
		return "before " + stamp(to)
	}
	return stamp(from) + " to " + stamp(to)
}

func cmdAuditVerify(a *app, ctx context.Context, fs *flag.FlagSet, args []string) error {
	asJSON := fs.Bool("json", false, "print JSON")
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
	res, err := ac.AuditVerify(ctx, slug)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeJSON(a.out, res); err != nil {
			return err
		}
		if !res.OK {
			return exitCode{code: exitChainBroken}
		}
		return nil
	}
	switch {
	case res.OK && res.Entries == 0:
		fmt.Fprintf(a.out, "The audit chain for %s is empty: nothing has been recorded yet.\n", slug)
	case res.OK:
		fmt.Fprintf(a.out, "The audit chain for %s is %s: %d entries, head %s.\n", slug, a.st.green("intact"), res.Entries, shortHash(res.Head))
	default:
		fmt.Fprintf(a.out, "The audit chain for %s is %s at entry %d: %s.\n", slug, a.st.red("BROKEN"), res.BadAt, res.Reason)
		if res.Entries > 0 {
			fmt.Fprintf(a.out, "Entries 1 to %d verify; the last good head is %s.\n", res.Entries, shortHash(res.Head))
		}
		fmt.Fprintln(a.out, "Treat this as an incident: keep the relay's data directory as it is and export the log before anything else changes.")
		return exitCode{code: exitChainBroken}
	}
	return nil
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:12] + "…" + h[len(h)-4:]
}
