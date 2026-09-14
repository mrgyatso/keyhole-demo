package fstools

import (
	"errors"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/mrgyatso/keyhole/internal/proto"
)

func (c *call) readFile(a proto.ReadFileArgs) (proto.ReadFileResult, error) {
	if a.Length < 0 {
		return proto.ReadFileResult{}, failf(proto.ErrBadRequest, "length must not be negative")
	}
	t, err := c.open(a.Path)
	if err != nil {
		return proto.ReadFileResult{}, err
	}
	defer t.close()
	if t.info.IsDir() {
		return proto.ReadFileResult{}, failf(proto.ErrNotRegular, "%s is a directory; use list_dir", a.Path)
	}
	size := t.info.Size()
	res := proto.ReadFileResult{Path: t.path, Size: size, ModTime: t.info.ModTime().UTC()}
	head, err := readAt(t.file, 0, min(size, sniffBytes))
	if err != nil {
		return proto.ReadFileResult{}, failf(proto.ErrIO, "reading %s: %v", a.Path, err)
	}
	enc := sniff(head)
	if enc == encBinary {
		res.Binary = true
		return res, nil
	}

	start, n := sliceBounds(size, a, c.caps.maxRead)
	var header int64 // bytes before the text: the UTF-16 byte-order mark
	if enc != encUTF8 {
		header = 2
		start, n = alignUTF16(start, n, header)
	}
	buf, err := readAt(t.file, start, n)
	if err != nil {
		return proto.ReadFileResult{}, failf(proto.ErrIO, "reading %s: %v", a.Path, err)
	}
	cutStart, cutEnd := start > header, start+int64(len(buf)) < size
	var skip, drop int
	var text string
	if enc == encUTF8 {
		skip, drop = trimPartialRunes(buf, cutStart, cutEnd)
		text = strings.ToValidUTF8(string(buf[skip:len(buf)-drop]), "�")
	} else {
		order := enc.order()
		skip, drop = trimPartialSurrogates(buf, order, cutStart, cutEnd)
		d := utf16Decoder{order: order}
		text = string(d.decode(nil, buf[skip:len(buf)-drop], true))
	}
	res.Offset = start + int64(skip)
	res.Length = int64(len(buf) - skip - drop)
	res.Truncated = res.Offset > header || res.Offset+res.Length < size

	content, count, rules := c.redact(text)
	c.noteRedactions(count, rules)
	res.Content = content
	return res, nil
}

// sliceBounds applies ReadFileArgs' offset and length semantics under the
// read cap: tail by default, negative offsets count from the end.
func sliceBounds(size int64, a proto.ReadFileArgs, limit int64) (start, n int64) {
	length := a.Length
	if length == 0 || length > limit {
		length = limit
	}
	switch {
	case a.Offset == 0 && a.Length == 0 && size > limit:
		start = size - limit
	case a.Offset >= 0:
		start = min(a.Offset, size)
	default:
		start = max(0, size+a.Offset)
	}
	return start, min(length, size-start)
}

// alignUTF16 moves a byte slice onto whole code units after the
// byte-order mark.
func alignUTF16(start, n, header int64) (int64, int64) {
	end := start + n
	start = max(start, header)
	if (start-header)%2 != 0 {
		start++
	}
	if (end-header)%2 != 0 {
		end--
	}
	return start, max(0, end-start)
}

// trimPartialRunes returns how many bytes to drop at each end of buf so it
// neither starts nor ends inside a UTF-8 sequence cut by the slice.
func trimPartialRunes(buf []byte, cutStart, cutEnd bool) (skip, drop int) {
	if cutStart {
		for skip < len(buf) && skip < utf8.UTFMax-1 && !utf8.RuneStart(buf[skip]) {
			skip++
		}
	}
	if cutEnd {
		for i := len(buf) - 1; i >= skip && i >= len(buf)-utf8.UTFMax; i-- {
			if utf8.RuneStart(buf[i]) {
				if !utf8.FullRune(buf[i:]) {
					drop = len(buf) - i
				}
				break
			}
		}
	}
	return skip, drop
}

func readAt(f *os.File, off, n int64) ([]byte, error) {
	buf := make([]byte, n)
	k, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:k], nil
}
