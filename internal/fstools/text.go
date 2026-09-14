package fstools

import (
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// sniffBytes is how much of a file's start decides text or binary.
const sniffBytes = 8 << 10

type encoding int

const (
	encUTF8 encoding = iota
	encUTF16LE
	encUTF16BE
	encBinary
)

func (e encoding) order() binary.ByteOrder {
	if e == encUTF16BE {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// sniff classifies a file by its first bytes: UTF-16 when it starts with a
// byte-order mark (common for Windows logs), binary when it holds a NUL
// byte or is mostly invalid UTF-8, UTF-8 otherwise. Text in a legacy 8-bit
// code page stays text; its stray bytes become U+FFFD.
func sniff(head []byte) encoding {
	switch {
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}):
		return encUTF16LE
	case bytes.HasPrefix(head, []byte{0xFE, 0xFF}):
		return encUTF16BE
	case bytes.IndexByte(head, 0) >= 0:
		return encBinary
	}
	invalid := 0
	for i := 0; i < len(head); {
		r, size := utf8.DecodeRune(head[i:])
		if r == utf8.RuneError && size == 1 {
			if !utf8.FullRune(head[i:]) {
				break // a sequence cut by the end of the sample
			}
			invalid++
		}
		i += size
	}
	if invalid*10 > len(head)*3 {
		return encBinary
	}
	return encUTF8
}

// trimPartialSurrogates returns how many bytes to drop at each end of a
// UTF-16 slice so it neither starts with the low half nor ends with the
// high half of a surrogate pair cut by the slice.
func trimPartialSurrogates(buf []byte, order binary.ByteOrder, cutStart, cutEnd bool) (skip, drop int) {
	if cutStart && len(buf) >= 2 && isLowSurrogate(rune(order.Uint16(buf))) {
		skip = 2
	}
	if cutEnd && len(buf)-skip >= 2 && isHighSurrogate(rune(order.Uint16(buf[len(buf)-2:]))) {
		drop = 2
	}
	return skip, drop
}

func isHighSurrogate(r rune) bool { return 0xD800 <= r && r <= 0xDBFF }
func isLowSurrogate(r rune) bool  { return 0xDC00 <= r && r <= 0xDFFF }

// utf16Decoder converts UTF-16 to UTF-8 incrementally, carrying an odd byte
// and a pending high surrogate between calls. Unpaired surrogates become
// U+FFFD.
type utf16Decoder struct {
	order   binary.ByteOrder
	odd     byte
	hasOdd  bool
	pending rune // high surrogate awaiting its pair, or 0
}

// decode appends the UTF-8 for src to dst. With final set, anything left
// incomplete is flushed as U+FFFD.
func (d *utf16Decoder) decode(dst, src []byte, final bool) []byte {
	if d.hasOdd && len(src) > 0 {
		dst = d.unit(dst, rune(d.order.Uint16([]byte{d.odd, src[0]})))
		src, d.hasOdd = src[1:], false
	}
	for ; len(src) >= 2; src = src[2:] {
		dst = d.unit(dst, rune(d.order.Uint16(src)))
	}
	if len(src) == 1 {
		d.odd, d.hasOdd = src[0], true
	}
	if final && (d.pending != 0 || d.hasOdd) {
		dst = utf8.AppendRune(dst, utf8.RuneError)
		d.pending, d.hasOdd = 0, false
	}
	return dst
}

func (d *utf16Decoder) unit(dst []byte, u rune) []byte {
	if d.pending != 0 {
		high := d.pending
		d.pending = 0
		if isLowSurrogate(u) {
			return utf8.AppendRune(dst, utf16.DecodeRune(high, u))
		}
		dst = utf8.AppendRune(dst, utf8.RuneError)
	}
	switch {
	case isHighSurrogate(u):
		d.pending = u
		return dst
	case isLowSurrogate(u):
		return utf8.AppendRune(dst, utf8.RuneError)
	}
	return utf8.AppendRune(dst, u)
}

// utf16Reader streams a UTF-16 source as UTF-8.
type utf16Reader struct {
	src  io.Reader
	dec  utf16Decoder
	in   []byte
	obuf []byte
	out  []byte // undelivered part of obuf
	err  error
}

func newUTF16Reader(src io.Reader, order binary.ByteOrder) *utf16Reader {
	return &utf16Reader{src: src, dec: utf16Decoder{order: order}, in: make([]byte, 32<<10)}
}

func (r *utf16Reader) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		n, err := r.src.Read(r.in)
		r.obuf = r.dec.decode(r.obuf[:0], r.in[:n], err != nil)
		r.out, r.err = r.obuf, err
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}
