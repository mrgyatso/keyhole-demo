package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/mrgyatso/keyhole/internal/adminapi"
	"github.com/mrgyatso/keyhole/internal/audit"
)

func TestAuditExportAndVerify(t *testing.T) {
	var gotMeta ReportMeta
	h := newHarness(t, func(c *Config) {
		c.Reports = map[string]ReportWriter{
			"csv": func(w io.Writer, meta ReportMeta, entries []audit.Entry, v audit.VerifyResult) error {
				gotMeta = meta
				_, err := fmt.Fprintf(w, "client=%s name=%s entries=%d ok=%v\n", meta.Client, meta.ClientName, len(entries), v.OK)
				return err
			},
		}
	})
	h.createClient("acme")
	h.must(adminapi.RouteDisableClient, []string{"acme"}, nil, nil)
	h.must(adminapi.RouteEnableClient, []string{"acme"}, nil, nil)

	export := func(q url.Values) reply {
		_, pattern := adminapi.Split(adminapi.RouteAuditExport)
		return h.do(http.MethodGet, h.priv.URL+adminapi.Fill(pattern, "acme")+"?"+q.Encode(), nil, h.adminHeader())
	}

	t.Run("jsonl", func(t *testing.T) {
		r := export(url.Values{"format": {"jsonl"}})
		if r.status != http.StatusOK || r.header.Get("Content-Type") != "application/x-ndjson" {
			t.Fatalf("%d %s", r.status, r.header.Get("Content-Type"))
		}
		var n uint64
		sc := bufio.NewScanner(bytes.NewReader(r.body))
		for sc.Scan() {
			var e audit.Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatal(err)
			}
			n++
			if e.N != n || e.Client != "acme" {
				t.Fatalf("line %d: %+v", n, e)
			}
		}
		if n != 3 {
			t.Fatalf("%d lines, want 3", n)
		}
		future := time.Now().Add(time.Hour).Format(time.RFC3339)
		if r := export(url.Values{"format": {"jsonl"}, "from": {future}}); r.status != http.StatusOK || len(r.body) != 0 {
			t.Fatalf("empty range: %d %q", r.status, r.body)
		}
	})

	t.Run("report formats come from Config.Reports", func(t *testing.T) {
		r := export(url.Values{"from": {"2020-01-01T00:00:00Z"}}) // csv is the default
		if r.status != http.StatusOK || r.header.Get("Content-Type") != "text/csv; charset=utf-8" {
			t.Fatalf("%d %s %s", r.status, r.header.Get("Content-Type"), r.body)
		}
		if string(r.body) != "client=acme name=ACME entries=3 ok=true\n" {
			t.Fatalf("report %q", r.body)
		}
		if gotMeta.From.Year() != 2020 || !gotMeta.To.IsZero() || gotMeta.GeneratedAt.IsZero() {
			t.Fatalf("meta %+v", gotMeta)
		}
		for _, q := range []url.Values{
			{"format": {"pdf"}}, // not configured in this relay
			{"format": {"xml"}},
			{"from": {"yesterday"}},
			{"from": {"2026-02-01T00:00:00Z"}, "to": {"2026-01-01T00:00:00Z"}},
		} {
			if r := export(q); r.status != http.StatusBadRequest {
				t.Errorf("%v: %d", q, r.status)
			}
		}
	})

	t.Run("verify", func(t *testing.T) {
		var v audit.VerifyResult
		h.must(adminapi.RouteAuditVerify, []string{"acme"}, nil, &v)
		if !v.OK || v.Entries != 3 {
			t.Fatalf("%+v", v)
		}
		h.audit.Tamper("acme", 2, func(e *audit.Entry) { e.Tech = "mallory" })
		h.must(adminapi.RouteAuditVerify, []string{"acme"}, nil, &v)
		if v.OK || v.BadAt != 2 {
			t.Fatalf("tampering not caught: %+v", v)
		}
	})

	t.Run("unknown client", func(t *testing.T) {
		for _, route := range []string{adminapi.RouteAuditExport, adminapi.RouteAuditVerify} {
			if r := h.call(route, []string{"nope"}, nil); r.status != http.StatusNotFound {
				t.Errorf("%s: %d", route, r.status)
			}
		}
	})
}
