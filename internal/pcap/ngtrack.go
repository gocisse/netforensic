package pcap

import (
	"encoding/binary"
	"io"
)

// pcapng block framing: every block starts with a 4-byte type and a 4-byte
// total length, and the section header block (type 0x0A0D0D0A) follows with
// a byte-order magic that tells how to read the lengths.
const (
	ngSectionHeaderType = 0x0a0d0d0a
	ngByteOrderMagic    = 0x1a2b3c4d
)

// blockTracker passes bytes through while following pcapng block framing, so
// that the end of the stream can be classified as clean (on a block boundary)
// or truncated (inside a block). gopacket's pcapng reader reports both as a
// plain io.EOF, which would hide truncated captures.
type blockTracker struct {
	r io.Reader

	order     binary.ByteOrder
	hdr       [12]byte
	hdrLen    int   // bytes of the current block header collected so far
	remaining int64 // bytes of the current block still to come after its header
	invalid   bool  // framing did not make sense; stop judging
}

// Read implements io.Reader.
func (t *blockTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.feed(p[:n])
	return n, err
}

// feed advances the framing state over b.
func (t *blockTracker) feed(b []byte) {
	for len(b) > 0 && !t.invalid {
		if t.remaining > 0 {
			skip := int64(len(b))
			if skip > t.remaining {
				skip = t.remaining
			}
			t.remaining -= skip
			b = b[skip:]
			continue
		}

		// Collect the block header: 8 bytes, or 12 for a section header.
		need := 8
		if t.hdrLen >= 4 && binary.LittleEndian.Uint32(t.hdr[:4]) == ngSectionHeaderType {
			need = 12
		}
		c := copy(t.hdr[t.hdrLen:need], b)
		t.hdrLen += c
		b = b[c:]
		if t.hdrLen < need {
			continue
		}
		// A section header's type is 4 bytes of a palindrome, so reading it
		// little-endian is correct for both byte orders; `need` may have just
		// become 12 now that 4 bytes are in, so loop once more if so.
		if t.hdrLen == 8 && binary.LittleEndian.Uint32(t.hdr[:4]) == ngSectionHeaderType {
			continue
		}

		if need == 12 {
			switch {
			case binary.LittleEndian.Uint32(t.hdr[8:12]) == ngByteOrderMagic:
				t.order = binary.LittleEndian
			case binary.BigEndian.Uint32(t.hdr[8:12]) == ngByteOrderMagic:
				t.order = binary.BigEndian
			default:
				t.invalid = true
				return
			}
		}
		if t.order == nil {
			t.invalid = true
			return
		}
		total := int64(t.order.Uint32(t.hdr[4:8]))
		if total < int64(need) {
			t.invalid = true
			return
		}
		t.remaining = total - int64(need)
		t.hdrLen = 0
	}
}

// midBlock reports whether the stream so far ends inside a block.
func (t *blockTracker) midBlock() bool {
	return !t.invalid && (t.hdrLen > 0 || t.remaining > 0)
}
