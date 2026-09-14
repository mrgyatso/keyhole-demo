package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ReportMeta describes the report being written.
type ReportMeta struct {
	Client      string // slug
	ClientName  string
	From, To    time.Time // the reporting period; a zero bound is open
	GeneratedAt time.Time
}

// CSVHeader is the column order of WriteCSV.
var CSVHeader = []string{
	"time", "kind", "tech", "session", "device", "hostname", "tool", "args",
	"resolved_path", "rule", "result", "error_code", "bytes", "sha256",
	"redactions", "n", "hash",
}

// csvTime is RFC 3339 in UTC with fixed millisecond precision, so the column
// sorts as text.
const csvTime = "2006-01-02T15:04:05.000Z07:00"

// WriteCSV writes entries as CSV: a header row, then one row per entry in the
// order given. Text a spreadsheet would evaluate as a formula (a leading =, +,
// -, @, tab or CR, which a device can put in a hostname or path) is prefixed
// with a single quote.
func WriteCSV(w io.Writer, entries []Entry) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return fmt.Errorf("audit: csv: %w", err)
	}
	for _, e := range entries {
		rec := []string{
			e.Time.UTC().Format(csvTime),
			e.Kind,
			cell(e.Tech),
			cell(e.SessionID),
			cell(e.DeviceID),
			cell(e.Hostname),
			cell(e.Tool),
			cell(compactJSON(e.Args)),
			cell(e.ResolvedPath),
			cell(e.RuleID),
			e.Result,
			cell(e.ErrorCode),
			strconv.FormatInt(e.Bytes, 10),
			e.SHA256,
			strconv.Itoa(e.Redactions),
			strconv.FormatUint(e.N, 10),
			e.Hash,
		}
		if err := cw.Write(rec); err != nil {
			return fmt.Errorf("audit: csv: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("audit: csv: %w", err)
	}
	return nil
}

// cell neutralises spreadsheet formula injection in a text cell.
func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return string(raw)
	}
	return b.String()
}

// entryPath is the path an entry is about: the canonical path the agent
// opened, or failing that the path the AI asked for.
func entryPath(e Entry) string {
	if e.ResolvedPath != "" {
		return e.ResolvedPath
	}
	var args struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(e.Args, &args)
	return args.Path
}

// period renders a report period for humans.
func period(m ReportMeta) string {
	from, to := "start of log", "report time"
	if !m.From.IsZero() {
		from = m.From.UTC().Format("2006-01-02 15:04 MST")
	}
	switch {
	case !m.To.IsZero():
		to = m.To.UTC().Format("2006-01-02 15:04 MST")
	case !m.GeneratedAt.IsZero():
		to = m.GeneratedAt.UTC().Format("2006-01-02 15:04 MST")
	}
	return from + " to " + to
}
