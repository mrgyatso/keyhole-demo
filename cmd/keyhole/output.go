package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// table writes aligned columns. The header row is upper-cased.
type table struct {
	tw *tabwriter.Writer
}

func newTable(w io.Writer, header ...string) *table {
	t := &table{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
	for i := range header {
		header[i] = strings.ToUpper(header[i])
	}
	t.row(header...)
	return t
}

func (t *table) row(cells ...string) {
	for i, c := range cells {
		if c == "" {
			cells[i] = "-"
		}
		cells[i] = strings.NewReplacer("\t", " ", "\n", " ").Replace(cells[i])
	}
	fmt.Fprintln(t.tw, strings.Join(cells, "\t"))
}

func (t *table) flush() { _ = t.tw.Flush() }

// kv writes aligned "key  value" lines.
func kv(w io.Writer, pairs ...[2]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range pairs {
		fmt.Fprintf(tw, "%s\t%s\n", p[0], p[1])
	}
	_ = tw.Flush()
}

// newAligned returns a tab writer for free-form aligned output.
func newAligned(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// stamp formats a time in the local zone for tables.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// ago renders how long before now t was, coarsely: "just now", "42s ago",
// "5m ago", "3h ago", "2d ago".
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < 5*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

// until renders how long after now t is: "in 12h", "in 89d", "expired".
func until(now, t time.Time) string {
	d := t.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes())+1)
	case d < 48*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	}
	return fmt.Sprintf("in %dd", int(d.Hours()/24))
}

// style is ANSI styling, on only when writing to a terminal and NO_COLOR is
// unset.
type style struct{ on bool }

func (s style) wrap(code, text string) string {
	if !s.on {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s style) bold(t string) string   { return s.wrap("1", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) red(t string) string    { return s.wrap("31", t) }
func (s style) green(t string) string  { return s.wrap("32", t) }
func (s style) yellow(t string) string { return s.wrap("33", t) }
