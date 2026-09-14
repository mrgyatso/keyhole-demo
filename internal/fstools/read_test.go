package fstools

import (
	"encoding/binary"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"unicode/utf16"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func readFile(t *testing.T, x *Executor, pol proto.Policy, args proto.ReadFileArgs) proto.ReadFileResult {
	t.Helper()
	return result[proto.ReadFileResult](t, run(t, x, proto.OpReadFile, args, pol))
}

func TestReadFileWhole(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.log")
	writeFile(t, p, "line1\nline2\n")
	r := readFile(t, New(Options{}), testPolicy(rootRule(root)), proto.ReadFileArgs{Path: p})
	if r.Content != "line1\nline2\n" || r.Size != 12 || r.Offset != 0 || r.Length != 12 || r.Truncated || r.Binary || r.Path != p || r.ModTime.IsZero() {
		t.Errorf("read = %+v", r)
	}
}

func TestReadFileSlices(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.log")
	writeFile(t, p, "0123456789abcdefghij") // 20 bytes
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	pol.MaxReadBytes = 10

	cases := []struct {
		name           string
		offset, length int64
		content        string
		wantOffset     int64
		truncated      bool
	}{
		{"tail by default", 0, 0, "abcdefghij", 10, true},
		{"explicit length reads the head", 0, 4, "0123", 0, true},
		{"offset and length", 5, 3, "567", 5, true},
		{"offset to the end", 15, 0, "fghij", 15, true},
		{"length clamped to the cap", 2, 100, "23456789ab", 2, true},
		{"negative offset is a tail", -4, 0, "ghij", 16, true},
		{"negative offset past the start", -100, 0, "0123456789", 0, true},
		{"offset past the end", 50, 0, "", 20, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := readFile(t, x, pol, proto.ReadFileArgs{Path: p, Offset: c.offset, Length: c.length})
			if r.Content != c.content || r.Offset != c.wantOffset || r.Length != int64(len(c.content)) || r.Truncated != c.truncated || r.Size != 20 {
				t.Errorf("read = %+v; want content %q at %d truncated=%v", r, c.content, c.wantOffset, c.truncated)
			}
		})
	}

	small := testPolicy(rootRule(root))
	r := readFile(t, x, small, proto.ReadFileArgs{Path: p, Offset: 10})
	if r.Content != "abcdefghij" || r.Truncated != true {
		t.Errorf("read from offset = %+v", r)
	}
	wantError(t, run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: p, Length: -1}, pol), proto.ErrBadRequest)
}

func TestReadFileTrimsPartialRunesAtTheEdges(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "utf8.log")
	writeFile(t, p, "aé€b") // a, C3 A9, E2 82 AC, b
	x := New(Options{})
	pol := testPolicy(rootRule(root))
	cases := []struct {
		offset, length, wantOffset, wantLength int64
		content                                string
	}{
		{2, 4, 3, 3, "€"}, // starts inside é: its continuation byte is dropped
		{1, 3, 1, 2, "é"}, // ends inside €: its lead byte is dropped
		{0, 0, 0, 7, "aé€b"},
	}
	for _, c := range cases {
		r := readFile(t, x, pol, proto.ReadFileArgs{Path: p, Offset: c.offset, Length: c.length})
		if r.Content != c.content || r.Offset != c.wantOffset || r.Length != c.wantLength {
			t.Errorf("read(%d, %d) = %q at %d+%d; want %q at %d+%d",
				c.offset, c.length, r.Content, r.Offset, r.Length, c.content, c.wantOffset, c.wantLength)
		}
	}
}

func TestReadFileReturnsMetadataOnlyForBinary(t *testing.T) {
	root := tempRoot(t)
	withNUL := filepath.Join(root, "a.bin")
	writeFile(t, withNUL, "MZ\x90\x00\x03\x00\x00\x00text")
	noise := make([]byte, 1000)
	for i := range noise {
		noise[i] = byte(0x80 + i%0x7f)
	}
	mostlyInvalid := filepath.Join(root, "b.bin")
	writeFile(t, mostlyInvalid, string(noise))
	latin1 := filepath.Join(root, "latin1.log")
	writeFile(t, latin1, "caf\xe9 ol\xe9\n")
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	for _, p := range []string{withNUL, mostlyInvalid} {
		r := readFile(t, x, pol, proto.ReadFileArgs{Path: p})
		if !r.Binary || r.Content != "" || r.Length != 0 || r.Size == 0 {
			t.Errorf("%s: read = %+v; want binary metadata only", filepath.Base(p), r)
		}
	}
	r := readFile(t, x, pol, proto.ReadFileArgs{Path: latin1})
	if r.Binary || r.Content != "caf� ol�\n" {
		t.Errorf("latin-1 text: %+v", r)
	}
}

func utf16File(order binary.ByteOrder, s string) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(units))
	order.PutUint16(b, 0xFEFF)
	for i, u := range units {
		order.PutUint16(b[2+2*i:], u)
	}
	return string(b)
}

func TestReadFileDecodesUTF16(t *testing.T) {
	root := tempRoot(t)
	le, be := filepath.Join(root, "le.log"), filepath.Join(root, "be.log")
	writeFile(t, le, utf16File(binary.LittleEndian, "hé\n😀"))
	writeFile(t, be, utf16File(binary.BigEndian, "hé\n😀"))
	cut := filepath.Join(root, "cut.log")
	writeFile(t, cut, utf16File(binary.LittleEndian, "ab😀c")) // BOM a b hi lo c: 12 bytes
	x := New(Options{})
	pol := testPolicy(rootRule(root))

	for _, p := range []string{le, be} {
		r := readFile(t, x, pol, proto.ReadFileArgs{Path: p})
		if r.Content != "hé\n😀" || r.Binary || r.Truncated || r.Offset != 2 || r.Length != 10 {
			t.Errorf("%s: read = %+v", filepath.Base(p), r)
		}
	}
	cases := []struct {
		name                   string
		maxRead                int64
		offset, length         int64
		content                string
		wantOffset, wantLength int64
	}{
		{"tail starting on a low surrogate", 4, 0, 0, "c", 10, 2},
		{"offset inside a code unit", 0, 3, 3, "b", 4, 2},
		{"no whole code unit in the slice", 0, 3, 2, "", 4, 0},
		{"end cutting a surrogate pair", 0, 2, 6, "ab", 2, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := testPolicy(rootRule(root))
			if c.maxRead > 0 {
				p.MaxReadBytes = c.maxRead
			}
			r := readFile(t, x, p, proto.ReadFileArgs{Path: cut, Offset: c.offset, Length: c.length})
			if r.Content != c.content || r.Offset != c.wantOffset || r.Length != c.wantLength || !r.Truncated {
				t.Errorf("read = %+v; want %q at %d+%d", r, c.content, c.wantOffset, c.wantLength)
			}
		})
	}
}

func TestReadFileRedactsContent(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.config")
	writeFile(t, p, "password=hunter2\nuser=bob hunter2\n")
	pol := testPolicy(rootRule(root))
	pol.Redact = true
	resp := run(t, New(Options{Redactor: fakeRedactor{"hunter2"}}), proto.OpReadFile, proto.ReadFileArgs{Path: p}, pol)
	r := result[proto.ReadFileResult](t, resp)
	if r.Content != "password=[REDACTED:test-secret]\nuser=bob [REDACTED:test-secret]\n" || r.Length != 34 {
		t.Errorf("read = %+v", r)
	}
	if resp.Meta.Redactions != 2 || !slices.Equal(resp.Meta.RedactionRules, []string{"test-secret"}) {
		t.Errorf("meta = %+v", resp.Meta)
	}
}

func TestReadFileRefusesDirectories(t *testing.T) {
	root := tempRoot(t)
	wantError(t, run(t, New(Options{}), proto.OpReadFile, proto.ReadFileArgs{Path: root}, testPolicy(rootRule(root))), proto.ErrNotRegular)
}

type panicRedactor struct{}

func (panicRedactor) Redact(string) (string, int, []string) { panic("redactor exploded") }

func TestExecuteRecoversFromPanics(t *testing.T) {
	root := tempRoot(t)
	p := filepath.Join(root, "app.log")
	writeFile(t, p, "text")
	pol := testPolicy(rootRule(root))
	pol.Redact = true
	x := New(Options{Redactor: panicRedactor{}, AgentVersion: "v", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	resp := run(t, x, proto.OpReadFile, proto.ReadFileArgs{Path: p}, pol)
	wantError(t, resp, proto.ErrInternal)
	if resp.ID != "req_test" || resp.Meta.AgentVersion != "v" || resp.Meta.AgentTime.IsZero() {
		t.Errorf("envelope after panic = %+v", resp)
	}
}
