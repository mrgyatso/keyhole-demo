package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWriteCSV(t *testing.T) {
	at := time.Date(2026, 9, 10, 14, 3, 22, 500_000_000, time.UTC)
	entries := []Entry{
		{N: 1, Time: at, Kind: KindTool, Client: "acme", DeviceID: "dev_a", Hostname: "SRV01", Tech: "alice@msp",
			SessionID: "ses_1", Tool: "read_file", Args: json.RawMessage(`{ "device": "srv01", "path": "C:\\Windows\\Logs\\CBS\\CBS.log" }`),
			ResolvedPath: `C:\Windows\Logs\CBS\CBS.log`, RuleID: "win-logs", Bytes: 2048, SHA256: "ab12", Redactions: 2,
			Result: ResultOK, Hash: "h1"},
		{N: 2, Time: at.Add(37500 * time.Millisecond).In(time.FixedZone("EST", -5*3600)), Kind: KindTool, Client: "acme",
			DeviceID: "dev_a", Hostname: `=HYPERLINK("x")`, Tech: "alice@msp", SessionID: "ses_1", Tool: "list_dir",
			Args: json.RawMessage(`{"device":"srv01","path":"C:\\Users"}`), Result: ResultDenied, ErrorCode: "not_allowed", Hash: "h2"},
		{N: 3, Time: at.Add(time.Hour), Kind: KindAdmin, Client: "acme", Tech: "bob", Tool: "client.disable",
			Args: json.RawMessage(`{"reason":"incident, see ticket"}`), Result: ResultOK, Hash: "h3"},
	}
	var b bytes.Buffer
	if err := WriteCSV(&b, entries); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"time,kind,tech,session,device,hostname,tool,args,resolved_path,rule,result,error_code,bytes,sha256,redactions,n,hash",
		`2026-09-10T14:03:22.500Z,tool,alice@msp,ses_1,dev_a,SRV01,read_file,"{""device"":""srv01"",""path"":""C:\\Windows\\Logs\\CBS\\CBS.log""}",C:\Windows\Logs\CBS\CBS.log,win-logs,ok,,2048,ab12,2,1,h1`,
		`2026-09-10T14:04:00.000Z,tool,alice@msp,ses_1,dev_a,"'=HYPERLINK(""x"")",list_dir,"{""device"":""srv01"",""path"":""C:\\Users""}",,,denied,not_allowed,0,,0,2,h2`,
		`2026-09-10T15:03:22.500Z,admin,bob,,,,client.disable,"{""reason"":""incident, see ticket""}",,,ok,,0,,0,3,h3`,
	}, "\n") + "\n"
	if got := b.String(); got != want {
		t.Fatalf("csv mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

// reportEntries builds a realistic chain: tool calls of every outcome, long and
// non-Latin paths, and control-plane changes.
func reportEntries(t *testing.T, n int) ([]Entry, VerifyResult) {
	t.Helper()
	ctx := context.Background()
	s := NewMemStore()
	base := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	add := func(e Entry) {
		e.Client = "acme"
		if err := s.Append(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}
	add(Entry{Time: base, Kind: KindEnroll, Tech: "installer", Tool: "device.enroll", DeviceID: "dev_srv01", Hostname: "SRV01",
		Args: json.RawMessage(`{"token_id":"tok_abc","os":"windows"}`), Result: ResultOK})
	add(Entry{Time: base.Add(time.Minute), Kind: KindAdmin, Tech: "zach@msp", Tool: "session.mint",
		Args: json.RawMessage(`{"session_id":"ses_1","tech":"alice@msp","ttl_minutes":720}`), Result: ResultOK})
	longPath := `C:\ProgramData\Vendor Application Suite\Diagnostics\Logs\` + strings.Repeat(`VeryLongSubdirectoryName\`, 14) + `service-2026-09-01.log`
	for i := range n {
		e := Entry{Time: base.Add(time.Duration(i+2) * time.Minute), Kind: KindTool, Tech: "alice@msp", SessionID: "ses_1",
			DeviceID: "dev_srv01", DeviceKey: "UABC", Hostname: "SRV01", AgentVersion: "v0.1.0", RequestID: fmt.Sprintf("req_%d", i),
			Tool: "read_file", ResolvedPath: `C:\Windows\Logs\CBS\CBS.log`, RuleID: "win-logs",
			Bytes: int64(1000 * i), SHA256: strings.Repeat("ab", 32), Redactions: i % 3, Result: ResultOK}
		switch i % 7 {
		case 1:
			e.Tool, e.ResolvedPath, e.Result, e.ErrorCode, e.Bytes = "list_dir", "", ResultDenied, "not_allowed", 0
			e.Args = json.RawMessage(`{"device":"srv01","path":"C:\\Users\\Administrator\\Documents"}`)
		case 2:
			e.ResolvedPath = longPath
		case 3:
			e.DeviceID, e.Hostname, e.ResolvedPath, e.Result, e.ErrorCode, e.Bytes = "", "", "", ResultDenied, "unknown_device", 0
			e.Args = json.RawMessage(`{"device":"globex-dc01","path":"C:\\Windows\\Logs"}`)
		case 4:
			e.Hostname, e.DeviceID, e.ResolvedPath = "сервер-01", "dev_ru", "/var/log/журнал/ошибки.log"
		case 5:
			e.Tool, e.Result, e.ErrorCode, e.Bytes = "grep", ResultError, "device_offline", 0
		}
		add(e)
	}
	add(Entry{Time: base.Add(time.Hour * 30), Kind: KindAdmin, Tech: "zach@msp", Tool: "client.disable",
		Args: json.RawMessage(`{"reason":"suspected prompt injection in a vendor log"}`), Result: ResultOK})

	var entries []Entry
	if err := s.Range(ctx, "acme", time.Time{}, time.Time{}, func(e Entry) error { entries = append(entries, e); return nil }); err != nil {
		t.Fatal(err)
	}
	v, err := s.Verify(ctx, "acme")
	if err != nil || !v.OK {
		t.Fatalf("verify: %+v %v", v, err)
	}
	return entries, v
}

func renderPDF(t *testing.T, meta ReportMeta, entries []Entry, v VerifyResult) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WritePDF(&b, meta, entries, v); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) || !bytes.Contains(out[max(0, len(out)-64):], []byte("%%EOF")) {
		t.Fatalf("not a complete PDF (%d bytes)", len(out))
	}
	return out
}

func pdfPages(pdf []byte) int {
	return bytes.Count(pdf, []byte("/Type /Page")) - bytes.Count(pdf, []byte("/Type /Pages"))
}

func TestWritePDF(t *testing.T) {
	entries, v := reportEntries(t, 150)
	meta := ReportMeta{Client: "acme", ClientName: "ACME Corp — Head Office", GeneratedAt: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
		From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)}
	out := renderPDF(t, meta, entries, v)
	if p := pdfPages(out); p < 4 {
		t.Fatalf("150 calls should span several pages, got %d", p)
	}
	// Same inputs, same bytes: a report can be regenerated and compared.
	if again := renderPDF(t, meta, entries, v); !bytes.Equal(out, again) {
		t.Fatal("PDF output is not deterministic")
	}
}

func TestWritePDFBrokenAndEmpty(t *testing.T) {
	meta := ReportMeta{Client: "acme", ClientName: "ACME Corp", GeneratedAt: time.Now()}
	entries, _ := reportEntries(t, 3)
	renderPDF(t, meta, entries, VerifyResult{Client: "acme", Entries: 2, BadAt: 3, Reason: "hash mismatch: entry was altered"})
	if p := pdfPages(renderPDF(t, meta, nil, VerifyResult{Client: "acme", OK: true})); p != 1 {
		t.Fatalf("an empty report should be one page, got %d", p)
	}
}

func TestPDFTextLayout(t *testing.T) {
	r := newPDFReport(ReportMeta{Client: "acme"})
	r.font("", 7.5, colInk)
	if got := r.txt("café\tсервер"); got != "caf\xe9 ??????" {
		t.Fatalf("txt: %q", got)
	}

	path := r.txt(`C:\ProgramData\` + strings.Repeat(`Subdirectory\`, 30) + `final-file.log`)
	lines := r.wrapLines(path, 60, `\/ `, 3)
	if len(lines) != 3 || !strings.HasSuffix(lines[2], "final-file.log") || !strings.HasPrefix(lines[2], r.ellipsis) {
		t.Fatalf("long path should keep its file name on the last of 3 lines: %q", lines)
	}
	for _, l := range lines {
		if w := r.pdf.GetStringWidth(l); w > 60-2*r.cm+0.01 {
			t.Fatalf("line %q is %.1fmm wide, over 60mm", l, w)
		}
	}
	if lines := r.wrapLines(r.txt(`/var/log/syslog`), 60, `\/ `, 3); len(lines) != 1 || lines[0] != "/var/log/syslog" {
		t.Fatalf("short path wrapped: %q", lines)
	}
	if got := r.fit(r.txt(strings.Repeat("x", 200)), 20); !strings.HasSuffix(got, r.ellipsis) || r.pdf.GetStringWidth(got) > 20 {
		t.Fatalf("fit: %q", got)
	}
}

func TestThousandsAndBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"} {
		if got := thousands(in); got != want {
			t.Errorf("thousands(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 2 << 20: "2.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
