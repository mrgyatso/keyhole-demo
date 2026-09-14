package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mrgyatso/keyhole/internal/audit"
	"github.com/mrgyatso/keyhole/internal/proto"
)

// formatJSONL is the built-in export format: one audit.Entry per line.
const formatJSONL = "jsonl"

var reportContentTypes = map[string]string{
	"csv": "text/csv; charset=utf-8",
	"pdf": "application/pdf",
}

// handleAuditExport serves RouteAuditExport: from and to (RFC 3339,
// optional) bound entry times, format picks jsonl or a configured report.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.st.Client(ctx, r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	from, to, err := parseRange(q.Get("from"), q.Get("to"))
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}
	now := time.Now().UTC()
	filename := fmt.Sprintf("keyhole-audit-%s-%s.%s", c.Slug, now.Format("20060102T150405Z"), format)
	if format == formatJSONL {
		s.exportJSONL(w, r, c.Slug, from, to, filename)
		return
	}
	render, ok := s.cfg.Reports[format]
	if !ok {
		badRequest(w, fmt.Sprintf("unknown format %q (available: %s)", format, strings.Join(s.exportFormats(), ", ")))
		return
	}
	var entries []audit.Entry
	if err := s.audit.Range(ctx, c.Slug, from, to, func(e audit.Entry) error {
		entries = append(entries, e)
		return nil
	}); err != nil {
		s.log.Error("audit export: read", "client", c.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "could not read the audit log")
		return
	}
	v, err := s.audit.Verify(ctx, c.Slug)
	if err != nil {
		s.log.Error("audit export: verify", "client", c.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "could not verify the audit log")
		return
	}
	var buf bytes.Buffer
	meta := ReportMeta{Client: c.Slug, ClientName: c.Name, From: from, To: to, GeneratedAt: now}
	if err := render(&buf, meta, entries, v); err != nil {
		s.log.Error("audit export: render", "client", c.Slug, "format", format, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "could not render the report")
		return
	}
	ct := reportContentTypes[format]
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// exportJSONL streams the entries as they are read. If reading fails after
// the first line went out, the connection is cut, so a truncated export can
// never pass for a complete one.
func (s *Server) exportJSONL(w http.ResponseWriter, r *http.Request, slug string, from, to time.Time, filename string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	enc := json.NewEncoder(w)
	wrote := false
	err := s.audit.Range(r.Context(), slug, from, to, func(e audit.Entry) error {
		wrote = true
		return enc.Encode(e)
	})
	if err != nil {
		s.log.Error("audit export: read", "client", slug, "err", err)
		if wrote {
			panic(http.ErrAbortHandler)
		}
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "could not read the audit log")
		return
	}
	if !wrote {
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) exportFormats() []string {
	formats := []string{formatJSONL}
	for f := range s.cfg.Reports {
		formats = append(formats, f)
	}
	slices.Sort(formats)
	return formats
}

func parseRange(fromS, toS string) (from, to time.Time, err error) {
	if fromS != "" {
		if from, err = time.Parse(time.RFC3339, fromS); err != nil {
			return from, to, errors.New("from must be an RFC 3339 time")
		}
	}
	if toS != "" {
		if to, err = time.Parse(time.RFC3339, toS); err != nil {
			return from, to, errors.New("to must be an RFC 3339 time")
		}
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return from, to, errors.New("from must be before to")
	}
	return from, to, nil
}

// handleAuditVerify serves RouteAuditVerify.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := s.st.Client(ctx, r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return
	}
	v, err := s.audit.Verify(ctx, c.Slug)
	if err != nil {
		s.log.Error("audit verify", "client", c.Slug, "err", err)
		writeError(w, http.StatusInternalServerError, proto.ErrInternal, "could not verify the audit log")
		return
	}
	writeJSON(w, http.StatusOK, v)
}
