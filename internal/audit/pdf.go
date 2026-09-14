package audit

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"
)

// WritePDF writes the human-readable AI access report for one client: chain
// verification, headline figures, summary tables, control-plane changes and
// every tool call in entries. v is the result of Verify over the client's
// whole chain, taken when entries were read. Times are shown in UTC.
func WritePDF(w io.Writer, meta ReportMeta, entries []Entry, v VerifyResult) error {
	r := newPDFReport(meta)
	st := summarize(entries)
	r.cover(st, v)
	r.summary(st)
	r.changes(st)
	r.accessLog(st)
	if err := r.pdf.Output(w); err != nil {
		return fmt.Errorf("audit: pdf: %w", err)
	}
	return nil
}

type rgb struct{ r, g, b int }

var (
	colInk    = rgb{31, 41, 55}
	colMuted  = rgb{107, 114, 128}
	colRule   = rgb{209, 213, 219}
	colHead   = rgb{243, 244, 246}
	colZebra  = rgb{249, 250, 251}
	colGood   = rgb{21, 128, 61}
	colGoodBg = rgb{240, 253, 244}
	colBad    = rgb{185, 28, 28}
	colBadBg  = rgb{254, 242, 242}
	colWarn   = rgb{180, 83, 9}
)

const (
	pageMargin = 12.0 // mm
	footerRoom = 14.0 // mm kept free at the bottom of every page
	lineH      = 4.0  // table text line height
	rowPad     = 1.2
	tsLayout   = "2006-01-02 15:04:05"
)

// codeText explains error codes to a non-technical reader.
var codeText = map[string]string{
	"not_allowed":      "outside the approved locations",
	"hard_denied":      "on the built-in deny list (credentials, keys, user data)",
	"unsafe_path":      "unsafe path form rejected",
	"unknown_device":   "no such device for this client",
	"ambiguous_device": "name matches more than one device",
	"device_offline":   "device offline",
	"device_revoked":   "device credential revoked",
	"client_disabled":  "access switched off for this client",
	"budget_exceeded":  "session read budget spent",
	"unauthorized":     "session expired or revoked",
	"audit_failed":     "not recorded, so nothing was returned",
	"not_found":        "file not found",
	"not_regular":      "not a regular file",
	"too_large":        "file over the size limit",
	"bad_request":      "malformed request",
	"io_error":         "read error on the device",
	"timeout":          "timed out",
	"internal":         "internal error",
	"unsupported_op":   "operation not supported by the agent",
}

type pdfReport struct {
	pdf      *fpdf.Fpdf
	tr       func(string) string
	meta     ReportMeta
	left     float64
	width    float64 // usable page width
	bottom   float64 // lowest y content may reach
	cm       float64 // cell margin
	ellipsis string
}

func newPDFReport(meta ReportMeta) *pdfReport {
	p := fpdf.New("L", "mm", "Letter", "")
	r := &pdfReport{pdf: p, meta: meta, left: pageMargin}
	r.tr = p.UnicodeTranslatorFromDescriptor("")
	pw, ph := p.GetPageSize()
	r.width, r.bottom = pw-2*pageMargin, ph-footerRoom
	r.cm = p.GetCellMargin()
	r.ellipsis = r.tr("…")

	p.SetMargins(pageMargin, pageMargin, pageMargin)
	p.SetAutoPageBreak(false, footerRoom) // rows break pages themselves, keeping each row whole
	p.AliasNbPages("")
	p.SetTitle("Keyhole AI access report: "+clientLabel(meta), true)
	p.SetSubject("AI file access audit, "+period(meta), true)
	p.SetAuthor("Keyhole", true)
	p.SetCreator("Keyhole", true)
	if !meta.GeneratedAt.IsZero() {
		p.SetCreationDate(meta.GeneratedAt.UTC())
		p.SetModificationDate(meta.GeneratedAt.UTC())
	}
	p.SetCatalogSort(true) // same inputs, same bytes
	p.SetHeaderFunc(r.header)
	p.SetFooterFunc(r.footer)
	p.AddPage()
	return r
}

func clientLabel(m ReportMeta) string {
	if m.ClientName == "" || m.ClientName == m.Client {
		return m.Client
	}
	return m.ClientName + " (" + m.Client + ")"
}

func (r *pdfReport) header() {
	if r.pdf.PageNo() == 1 {
		return
	}
	r.font("", 7.5, colMuted)
	r.pdf.SetXY(r.left, 7)
	r.pdf.CellFormat(r.width/2, 4, r.txt("Keyhole AI access report  |  "+clientLabel(r.meta)), "", 0, "L", false, 0, "")
	r.pdf.CellFormat(r.width/2, 4, r.txt(period(r.meta)), "", 0, "R", false, 0, "")
	r.rule(r.left, 12, r.width, colRule)
	r.pdf.SetXY(r.left, 15)
}

func (r *pdfReport) footer() {
	_, ph := r.pdf.GetPageSize()
	y := ph - 10
	r.rule(r.left, y-1.5, r.width, colRule)
	r.font("", 7, colMuted)
	left := "Keyhole AI access report  |  " + clientLabel(r.meta)
	if !r.meta.GeneratedAt.IsZero() {
		left += "  |  generated " + r.meta.GeneratedAt.UTC().Format("2006-01-02 15:04 MST")
	}
	r.pdf.SetXY(r.left, y)
	r.pdf.CellFormat(r.width*0.75, 4, r.txt(left), "", 0, "L", false, 0, "")
	r.pdf.CellFormat(r.width*0.25, 4, fmt.Sprintf("Page %d of {nb}", r.pdf.PageNo()), "", 0, "R", false, 0, "")
}

// cover writes the first page: identity, verification, headline figures and
// what the report is.
func (r *pdfReport) cover(st *stats, v VerifyResult) {
	p := r.pdf
	p.SetXY(r.left, pageMargin)
	r.font("B", 20, colInk)
	p.CellFormat(r.width, 10, r.txt("Keyhole AI access report"), "", 1, "L", false, 0, "")
	r.font("", 13, colInk)
	p.CellFormat(r.width, 7, r.txt(clientLabel(r.meta)), "", 1, "L", false, 0, "")
	p.Ln(2)
	gen := "-"
	if !r.meta.GeneratedAt.IsZero() {
		gen = r.meta.GeneratedAt.UTC().Format("2006-01-02 15:04:05 MST")
	}
	r.field("Period", period(r.meta))
	r.field("Generated", gen)
	r.field("Entries", entriesLine(st))
	p.Ln(4)
	r.verification(v)
	p.Ln(5)
	r.figures(st)
	p.Ln(6)
	r.font("B", 9, colInk)
	p.SetX(r.left)
	p.CellFormat(r.width, 5, r.txt("About this report"), "", 1, "L", false, 0, "")
	r.para(aboutText, 8.5, 4.2, colInk, r.left, r.width*0.8)
}

const aboutText = "Keyhole lets an AI assistant read log and configuration files on this client's machines. " +
	"Access is read-only and limited to approved locations; a built-in deny list keeps credentials, keys and user data out of reach, " +
	"and secrets found in files are redacted on the device before anything leaves it. " +
	"Every request is recorded, including refused ones: the technician's session, the device, the exact path, the outcome and " +
	"the SHA-256 of the content the AI received. Entries are kept in an append-only log in this client's own isolated account, " +
	"and each entry includes the hash of the one before it, so altering, removing or reordering any entry breaks the chain verified above."

func entriesLine(st *stats) string {
	if st.n == 0 {
		return "none in this period"
	}
	return fmt.Sprintf("%s in this period (audit chain positions %s to %s)", thousands(st.n), thousands(st.firstN), thousands(st.lastN))
}

func (r *pdfReport) field(label, value string) {
	r.pdf.SetX(r.left)
	r.font("B", 8.5, colMuted)
	r.pdf.CellFormat(22, 5, r.txt(label), "", 0, "L", false, 0, "")
	r.font("", 8.5, colInk)
	r.pdf.CellFormat(r.width-22, 5, r.txt(value), "", 1, "L", false, 0, "")
}

// verification draws the chain-verification panel.
func (r *pdfReport) verification(v VerifyResult) {
	title, fg, bg := "Audit chain verified", colGood, colGoodBg
	var body string
	switch {
	case !v.OK:
		title, fg, bg = fmt.Sprintf("Audit chain BROKEN at entry %d", v.BadAt), colBad, colBadBg
		body = fmt.Sprintf("%s. Entries 1 to %d verify; entry %d and everything after it cannot be relied on. Investigate before sharing this report.",
			v.Reason, v.Entries, v.BadAt)
	case v.Entries == 0:
		body = "The client's audit log is empty."
	default:
		body = fmt.Sprintf("All %s entries in the client's audit log, from the first to the latest, were re-hashed and link correctly: none has been altered, removed or reordered.",
			thousands(v.Entries))
	}
	x, w := r.left+5, r.width-10
	r.font("", 8.5, colInk)
	lines := r.wrap(r.txt(body), w, " ")
	h := 4 + 6 + float64(len(lines))*4.2 + 3
	if v.Head != "" {
		h += 5
	}
	y := r.pdf.GetY()
	r.fillRect(r.left, y, r.width, h, bg)
	r.fillRect(r.left, y, 1.5, h, fg)
	r.pdf.SetXY(x, y+3)
	r.font("B", 11, fg)
	r.pdf.CellFormat(w, 6, r.txt(title), "", 0, "L", false, 0, "")
	r.font("", 8.5, colInk)
	for i, line := range lines {
		r.pdf.SetXY(x, y+9+float64(i)*4.2)
		r.pdf.CellFormat(w, 4.2, line, "", 0, "L", false, 0, "")
	}
	if v.Head != "" {
		r.pdf.SetXY(x, y+9+float64(len(lines))*4.2+0.8)
		r.font("B", 8, colMuted)
		r.pdf.CellFormat(24, 4.2, "Chain head", "", 0, "L", false, 0, "")
		r.pdf.SetFont("Courier", "", 8)
		r.pdf.CellFormat(w-24, 4.2, r.txt(v.Head), "", 0, "L", false, 0, "")
	}
	r.pdf.SetXY(r.left, y+h)
}

// figures draws the row of headline numbers.
func (r *pdfReport) figures(st *stats) {
	figs := []struct{ label, value string }{
		{"AI tool calls", thousands(st.total.calls)},
		{"Allowed", thousands(st.total.ok)},
		{"Denied", thousands(st.total.denied)},
		{"Errors", thousands(st.total.errs)},
		{"Content returned", formatBytes(st.total.bytes)},
		{"Secrets redacted", thousands(st.total.redactions)},
		{"Devices accessed", thousands(len(st.byDevice))},
		{"Admin changes", thousands(len(st.changes))},
	}
	const gap = 2.5
	tw := (r.width - gap*float64(len(figs)-1)) / float64(len(figs))
	y := r.pdf.GetY()
	for i, f := range figs {
		x := r.left + float64(i)*(tw+gap)
		r.fillRect(x, y, tw, 16, colHead)
		r.pdf.SetXY(x+1, y+2.5)
		r.font("B", 14, colInk)
		r.pdf.CellFormat(tw-2, 7, r.fit(r.txt(f.value), tw-2), "", 0, "L", false, 0, "")
		r.pdf.SetXY(x+1, y+10)
		r.font("", 7, colMuted)
		r.pdf.CellFormat(tw-2, 4, r.fit(r.txt(f.label), tw-2), "", 0, "L", false, 0, "")
	}
	r.pdf.SetXY(r.left, y+16)
}

func (r *pdfReport) summary(st *stats) {
	r.heading("Summary", "")
	if st.total.calls == 0 {
		r.para("No AI tool calls were recorded in this period.", 8.5, 4.2, colMuted, r.left, r.width)
		return
	}

	r.subheading("Calls by tool")
	cols := []column{{"Tool", 50, "L"}, {"Calls", 22, "R"}, {"Allowed", 22, "R"}, {"Denied", 22, "R"},
		{"Errors", 22, "R"}, {"Content", 26, "R"}, {"Redactions", 24, "R"}}
	var rows [][]tcell
	for _, k := range byCalls(st.byTool) {
		t := st.byTool[k]
		rows = append(rows, r.cells(cols, k, thousands(t.calls), thousands(t.ok), thousands(t.denied),
			thousands(t.errs), formatBytes(t.bytes), thousands(t.redactions)))
	}
	r.table(cols, rows)

	r.subheading("Outcomes")
	cols = []column{{"Result", 30, "L"}, {"Reason", 120, "L"}, {"Calls", 22, "R"}}
	keys := slices.Collect(maps.Keys(st.outcomes))
	slices.SortFunc(keys, func(a, b outcome) int {
		return cmp.Or(cmp.Compare(st.outcomes[b], st.outcomes[a]), strings.Compare(a.result, b.result), strings.Compare(a.code, b.code))
	})
	rows = rows[:0]
	for _, k := range keys {
		reason := "-"
		if k.code != "" {
			reason = k.code
			if t := codeText[k.code]; t != "" {
				reason += ": " + t
			}
		}
		row := r.cells(cols, k.result, reason, thousands(st.outcomes[k]))
		row[0].c = resultColor(k.result)
		rows = append(rows, row)
	}
	r.table(cols, rows)

	r.subheading("Calls by technician")
	cols = []column{{"Technician", 70, "L"}, {"Sessions", 22, "R"}, {"Calls", 22, "R"}, {"Denied", 22, "R"},
		{"Content", 26, "R"}, {"Last call (UTC)", 36, "L"}}
	rows = rows[:0]
	for _, k := range byCalls(st.byTech) {
		t := st.byTech[k]
		rows = append(rows, r.cells(cols, cmp.Or(k, "-"), thousands(len(t.sessions)), thousands(t.calls),
			thousands(t.denied), formatBytes(t.bytes), t.last.UTC().Format(tsLayout)))
	}
	r.table(cols, rows)

	r.subheading("Calls by device")
	cols = []column{{"Device", 50, "L"}, {"Device ID", 42, "L"}, {"Calls", 22, "R"}, {"Denied", 22, "R"},
		{"Content", 26, "R"}, {"Redactions", 24, "R"}, {"Last call (UTC)", 36, "L"}}
	rows = rows[:0]
	if len(st.byDevice) == 0 {
		r.para("No call reached a device.", 8.5, 4.2, colMuted, r.left, r.width)
	} else {
		for _, id := range byCalls(st.byDevice) {
			t := st.byDevice[id]
			rows = append(rows, r.cells(cols, cmp.Or(st.hostname[id], "-"), id, thousands(t.calls), thousands(t.denied),
				formatBytes(t.bytes), thousands(t.redactions), t.last.UTC().Format(tsLayout)))
		}
		r.table(cols, rows)
	}
	r.para(fmt.Sprintf("Total content returned to the AI: %s (%s bytes). Total secrets redacted on the devices: %s.",
		formatBytes(st.total.bytes), thousands(st.total.bytes), thousands(st.total.redactions)), 8.5, 4.2, colInk, r.left, r.width)
}

func (r *pdfReport) changes(st *stats) {
	r.heading("Control-plane changes", "Enrollments and administrative actions: policy edits, kill switch, revocations, session and token minting.")
	if len(st.changes) == 0 {
		r.para("No control-plane changes in this period.", 8.5, 4.2, colMuted, r.left, r.width)
		return
	}
	cols := []column{{"#", 14, "R"}, {"Time (UTC)", 30, "L"}, {"Actor", 40, "L"}, {"Change", 38, "L"},
		{"Device", 36, "L"}, {"Details", 0, "L"}, {"Result", 30, "L"}}
	fill(cols, r.width)
	var rows [][]tcell
	for _, e := range st.changes {
		row := r.cells(cols, thousands(e.N), e.Time.UTC().Format(tsLayout), cmp.Or(e.Tech, "-"), e.Tool,
			cmp.Or(e.Hostname, e.DeviceID, "-"), "", resultLabel(e))
		row[5].lines = r.wrapLines(r.txt(compactJSON(e.Args)), cols[5].w, ",", 2)
		row[6].c = resultColor(e.Result)
		rows = append(rows, row)
	}
	r.table(cols, rows)
}

func (r *pdfReport) accessLog(st *stats) {
	if len(st.calls) == 0 {
		return
	}
	r.pdf.AddPage()
	r.heading("AI access log", "Every tool call in the period, in audit-chain order. Content is what the AI received, after redaction.")
	cols := []column{{"#", 12, "R"}, {"Time (UTC)", 29, "L"}, {"Technician", 26, "L"}, {"Device", 28, "L"},
		{"Tool", 21, "L"}, {"Path", 0, "L"}, {"Result", 30, "L"}, {"Content", 16, "R"}, {"Redact.", 13, "R"}}
	fill(cols, r.width)
	var rows [][]tcell
	for _, e := range st.calls {
		row := r.cells(cols, thousands(e.N), e.Time.UTC().Format(tsLayout), e.Tech, deviceLabel(e), e.Tool,
			"", resultLabel(e), formatBytes(e.Bytes), thousands(e.Redactions))
		row[5].lines = r.wrapLines(r.txt(cmp.Or(entryPath(e), "-")), cols[5].w, `\/ `, 3)
		row[6].c = resultColor(e.Result)
		rows = append(rows, row)
	}
	r.table(cols, rows)
}

func deviceLabel(e Entry) string {
	if d := cmp.Or(e.Hostname, e.DeviceID); d != "" {
		return d
	}
	var args struct {
		Device string `json:"device"`
	}
	if json.Unmarshal(e.Args, &args) == nil && args.Device != "" {
		return strconv.Quote(args.Device)
	}
	return "-"
}

func resultLabel(e Entry) string {
	if e.ErrorCode == "" {
		return e.Result
	}
	return e.Result + ": " + e.ErrorCode
}

func resultColor(result string) rgb {
	switch result {
	case ResultOK:
		return colInk
	case ResultDenied:
		return colBad
	default:
		return colWarn
	}
}

// Tables.

type column struct {
	title string
	w     float64 // mm; 0 takes the remaining width (see fill)
	align string
}

// tcell is one table cell: one or more lines, in color c (zero means ink).
type tcell struct {
	lines []string
	c     rgb
}

// fill gives the zero-width column whatever width the others leave.
func fill(cols []column, total float64) {
	used, flex := 0.0, -1
	for i, c := range cols {
		if c.w == 0 {
			flex = i
		}
		used += c.w
	}
	if flex >= 0 {
		cols[flex].w = total - used
	}
}

// cells makes a row of single-line cells, fitted to their columns.
func (r *pdfReport) cells(cols []column, vals ...string) []tcell {
	r.font("", 7.5, colInk)
	row := make([]tcell, len(cols))
	for i, v := range vals {
		row[i].lines = []string{r.fit(r.txt(v), cols[i].w)}
	}
	return row
}

func (r *pdfReport) table(cols []column, rows [][]tcell) {
	tw := 0.0
	for _, c := range cols {
		tw += c.w
	}
	r.tableHead(cols, tw)
	for i, row := range rows {
		n := 1
		for _, c := range row {
			n = max(n, len(c.lines))
		}
		h := float64(n)*lineH + 2*rowPad
		if r.pdf.GetY()+h > r.bottom {
			r.pdf.AddPage()
			r.tableHead(cols, tw)
		}
		y := r.pdf.GetY()
		if i%2 == 1 {
			r.fillRect(r.left, y, tw, h, colZebra)
		}
		x := r.left
		for j, col := range cols {
			r.font("", 7.5, cmp.Or(row[j].c, colInk))
			for k, line := range row[j].lines {
				r.pdf.SetXY(x, y+rowPad+float64(k)*lineH)
				r.pdf.CellFormat(col.w, lineH, line, "", 0, col.align, false, 0, "")
			}
			x += col.w
		}
		r.rule(r.left, y+h, tw, colRule)
		r.pdf.SetXY(r.left, y+h)
	}
	r.pdf.Ln(2)
}

func (r *pdfReport) tableHead(cols []column, tw float64) {
	r.ensure(6 + lineH + 2*rowPad)
	y := r.pdf.GetY()
	r.fillRect(r.left, y, tw, 6, colHead)
	r.font("B", 7.5, colInk)
	x := r.left
	for _, c := range cols {
		r.pdf.SetXY(x, y)
		r.pdf.CellFormat(c.w, 6, r.fit(r.txt(c.title), c.w), "", 0, c.align, false, 0, "")
		x += c.w
	}
	r.rule(r.left, y+6, tw, colMuted)
	r.pdf.SetXY(r.left, y+6)
}

// Text layout.

func (r *pdfReport) heading(title, note string) {
	r.ensure(30)
	r.pdf.Ln(3)
	r.pdf.SetX(r.left)
	r.font("B", 13, colInk)
	r.pdf.CellFormat(r.width, 7, r.txt(title), "", 1, "L", false, 0, "")
	if note != "" {
		r.para(note, 8, 4, colMuted, r.left, r.width)
	}
	r.pdf.Ln(1.5)
}

func (r *pdfReport) subheading(title string) {
	r.ensure(22)
	r.pdf.Ln(1)
	r.pdf.SetX(r.left)
	r.font("B", 9.5, colInk)
	r.pdf.CellFormat(r.width, 6, r.txt(title), "", 1, "L", false, 0, "")
}

func (r *pdfReport) para(s string, size, lh float64, c rgb, x, w float64) {
	r.font("", size, c)
	for _, line := range r.wrap(r.txt(s), w, " ") {
		r.ensure(lh)
		y := r.pdf.GetY()
		r.pdf.SetXY(x, y)
		r.pdf.CellFormat(w, lh, line, "", 0, "L", false, 0, "")
		r.pdf.SetXY(x, y+lh)
	}
}

// ensure starts a new page unless h more millimetres fit on this one.
func (r *pdfReport) ensure(h float64) {
	if r.pdf.GetY()+h > r.bottom {
		r.pdf.AddPage()
	}
}

func (r *pdfReport) font(style string, size float64, c rgb) {
	r.pdf.SetFont("Helvetica", style, size)
	r.pdf.SetTextColor(c.r, c.g, c.b)
}

func (r *pdfReport) fillRect(x, y, w, h float64, c rgb) {
	r.pdf.SetFillColor(c.r, c.g, c.b)
	r.pdf.Rect(x, y, w, h, "F")
}

func (r *pdfReport) rule(x, y, w float64, c rgb) {
	r.pdf.SetDrawColor(c.r, c.g, c.b)
	r.pdf.SetLineWidth(0.2)
	r.pdf.Line(x, y, x+w, y)
}

// txt converts s to the cp1252 bytes the core fonts use. Control characters
// become spaces and characters cp1252 lacks become '?'. All width
// measurement below works on its output, one byte per character.
func (r *pdfReport) txt(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == utf8.RuneError:
			b.WriteByte('?')
		case c < 0x20 || c == 0x7f:
			b.WriteByte(' ')
		case c < 0x80:
			b.WriteByte(byte(c))
		default:
			t := r.tr(string(c))
			if t == "." { // the translator's mark for an unmapped rune
				t = "?"
			}
			b.WriteString(t)
		}
	}
	return b.String()
}

func (r *pdfReport) widths(s string) (ws []float64, total float64) {
	ws = make([]float64, len(s))
	for i := range len(s) {
		ws[i] = r.pdf.GetStringWidth(s[i : i+1])
		total += ws[i]
	}
	return ws, total
}

// fit ellipsises s at the end so it fits a cell of width w.
func (r *pdfReport) fit(s string, w float64) string {
	avail := w - 2*r.cm
	ws, total := r.widths(s)
	if total <= avail {
		return s
	}
	avail -= r.pdf.GetStringWidth(r.ellipsis)
	n := len(s)
	for n > 0 && total > avail {
		n--
		total -= ws[n]
	}
	return s[:n] + r.ellipsis
}

// fitTail ellipsises s at the start, keeping its end (a file name) visible.
func (r *pdfReport) fitTail(s string, w float64) string {
	avail := w - 2*r.cm
	ws, total := r.widths(s)
	if total <= avail {
		return s
	}
	avail -= r.pdf.GetStringWidth(r.ellipsis)
	i := 0
	for i < len(s) && total > avail {
		total -= ws[i]
		i++
	}
	return r.ellipsis + s[i:]
}

// wrap breaks s into lines that fit width w, preferring to break after one
// of the characters in breakAfter and breaking mid-word only when it must.
func (r *pdfReport) wrap(s string, w float64, breakAfter string) []string {
	avail := w - 2*r.cm
	ws, _ := r.widths(s)
	var lines []string
	start, brk, lineW := 0, -1, 0.0
	for i := 0; i < len(s); i++ {
		if lineW+ws[i] > avail && i > start {
			cut := i
			if brk > start {
				cut = brk
			}
			lines = append(lines, strings.TrimRight(s[start:cut], " "))
			start, brk, lineW = cut, -1, 0
			for _, x := range ws[cut:i] {
				lineW += x
			}
		}
		lineW += ws[i]
		if strings.IndexByte(breakAfter, s[i]) >= 0 {
			brk = i + 1
		}
	}
	return append(lines, strings.TrimRight(s[start:], " "))
}

// wrapLines wraps s to at most maxLines lines; if it needs more, the last
// line shows the end of the text after an ellipsis.
func (r *pdfReport) wrapLines(s string, w float64, breakAfter string, maxLines int) []string {
	lines := r.wrap(s, w, breakAfter)
	if len(lines) <= maxLines {
		return lines
	}
	rest := strings.Join(lines[maxLines-1:], "")
	return append(lines[:maxLines-1], r.fitTail(rest, w))
}

// Aggregation.

type tally struct {
	calls, ok, denied, errs, redactions int
	bytes                               int64
	last                                time.Time
	sessions                            map[string]struct{}
}

func (t *tally) add(e Entry) {
	t.calls++
	switch e.Result {
	case ResultOK:
		t.ok++
	case ResultDenied:
		t.denied++
	default:
		t.errs++
	}
	t.bytes += e.Bytes
	t.redactions += e.Redactions
	if e.Time.After(t.last) {
		t.last = e.Time
	}
	if e.SessionID != "" {
		if t.sessions == nil {
			t.sessions = map[string]struct{}{}
		}
		t.sessions[e.SessionID] = struct{}{}
	}
}

type outcome struct{ result, code string }

type stats struct {
	n, firstN, lastN uint64
	total            tally // tool calls only
	byTool           map[string]*tally
	byTech           map[string]*tally
	byDevice         map[string]*tally // by device ID
	hostname         map[string]string // device ID -> hostname
	outcomes         map[outcome]int
	calls            []Entry // tool calls
	changes          []Entry // admin and enroll entries
}

func summarize(entries []Entry) *stats {
	st := &stats{byTool: map[string]*tally{}, byTech: map[string]*tally{}, byDevice: map[string]*tally{},
		hostname: map[string]string{}, outcomes: map[outcome]int{}}
	bump := func(m map[string]*tally, k string, e Entry) {
		if m[k] == nil {
			m[k] = &tally{}
		}
		m[k].add(e)
	}
	for _, e := range entries {
		st.n++
		if st.firstN == 0 || e.N < st.firstN {
			st.firstN = e.N
		}
		st.lastN = max(st.lastN, e.N)
		if e.Kind != KindTool {
			st.changes = append(st.changes, e)
			continue
		}
		st.calls = append(st.calls, e)
		st.total.add(e)
		bump(st.byTool, e.Tool, e)
		bump(st.byTech, e.Tech, e)
		if e.DeviceID != "" {
			bump(st.byDevice, e.DeviceID, e)
			if e.Hostname != "" {
				st.hostname[e.DeviceID] = e.Hostname
			}
		}
		st.outcomes[outcome{e.Result, e.ErrorCode}]++
	}
	return st
}

func byCalls(m map[string]*tally) []string {
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(a, b string) int {
		return cmp.Or(cmp.Compare(m[b].calls, m[a].calls), strings.Compare(a, b))
	})
	return keys
}

func thousands[T ~int | ~int64 | ~uint64](n T) string {
	s := strconv.FormatUint(uint64(max(n, 0)), 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	v, suffix := float64(n)/unit, "KiB"
	for _, s := range []string{"MiB", "GiB", "TiB"} {
		if v < unit {
			break
		}
		v, suffix = v/unit, s
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " " + suffix
}
