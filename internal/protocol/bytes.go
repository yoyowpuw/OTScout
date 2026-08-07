package protocol

import (
	"encoding/binary"
	"strings"
	"unicode"
)

// reader is a bounds checked cursor over a payload. Every decoder in this package
// reads through it, because these payloads come from untrusted sources: a packet
// capture handed over by someone else, or a reply from a device that may be
// broken or hostile. A single unchecked index would turn that into a panic.
type reader struct {
	buf []byte
	pos int
}

func newReader(buf []byte) *reader { return &reader{buf: buf} }

func (r *reader) remaining() int { return len(r.buf) - r.pos }

func (r *reader) has(n int) bool { return r.remaining() >= n }

func (r *reader) u8() (byte, bool) {
	if !r.has(1) {
		return 0, false
	}
	v := r.buf[r.pos]
	r.pos++
	return v, true
}

func (r *reader) u16be() (uint16, bool) {
	if !r.has(2) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) u16le() (uint16, bool) {
	if !r.has(2) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) u32le() (uint32, bool) {
	if !r.has(4) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *reader) u32be() (uint32, bool) {
	if !r.has(4) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || !r.has(n) {
		return nil, false
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, true
}

func (r *reader) skip(n int) bool {
	if n < 0 || !r.has(n) {
		return false
	}
	r.pos += n
	return true
}

func (r *reader) peek() (byte, bool) {
	if !r.has(1) {
		return 0, false
	}
	return r.buf[r.pos], true
}

// cleanASCII turns a fixed width protocol field into a displayable string.
//
// Device fields are padded with spaces or nulls, and a broken device may put
// anything at all in them. Non printable bytes are dropped rather than passed
// through, because these strings end up in HTML reports and in a terminal, and
// neither should be at the mercy of whatever a device chose to send.
func cleanASCII(raw []byte) string {
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, b := range raw {
		switch {
		case b == 0:
			// Fixed width fields are null padded, and the padding is not part
			// of the value.
			continue
		case b >= 0x20 && b < 0x7f:
			sb.WriteByte(b)
		default:
			// Anything else is replaced with a space so that word boundaries
			// survive without the byte itself leaking through.
			sb.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

// looksPrintable reports whether a byte slice is mostly readable text, used to
// decide whether a field is worth reporting at all.
func looksPrintable(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	printable := 0
	for _, b := range raw {
		if b == 0 {
			continue
		}
		if unicode.IsPrint(rune(b)) && b < 0x80 {
			printable++
		}
	}
	return printable*2 >= len(raw)
}
