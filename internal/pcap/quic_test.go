package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

// QUIC long header encoding for the tests.

func qVarint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(nil, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(nil, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(nil, v|0xc000000000000000)
}

// qLong builds a long header packet: the first byte with the type bits, the
// version, the connection IDs and what follows them.
func qLong(version uint32, typeBits byte, dcid, scid []byte, rest ...[]byte) []byte {
	b := []byte{0xc0 | typeBits<<4}
	b = binary.BigEndian.AppendUint32(b, version)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	for _, r := range rest {
		b = append(b, r...)
	}
	return b
}

// qInitial is an Initial (type bits 0 in v1, 1 in v2) with an empty token and
// a payload of the given size.
func qInitial(version uint32, dcid, scid []byte, payload int) []byte {
	bits := byte(0)
	if version == models.QUICVersion2 {
		bits = 1
	}
	return qLong(version, bits, dcid, scid, qVarint(0), qVarint(uint64(payload)), bytes.Repeat([]byte{0xaa}, payload))
}

// qSized is a 0-RTT or Handshake packet (type bits given), with a payload.
func qSized(version uint32, bits byte, dcid, scid []byte, payload int) []byte {
	return qLong(version, bits, dcid, scid, qVarint(uint64(payload)), bytes.Repeat([]byte{0xbb}, payload))
}

func qVersionNeg(dcid, scid []byte, offered ...uint32) []byte {
	b := []byte{0x80 | 0x2a} // the fixed bit and the type bits are unused
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	for _, v := range offered {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func TestFillQUIC(t *testing.T) {
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	s := []byte{9, 10, 11, 12}
	const draft29 = 0xff00001d

	tests := []struct {
		name     string
		payload  []byte
		src, dst uint16
		want     models.PacketInfo // zero means: not QUIC
	}{
		{
			name: "v1 Initial to port 443", payload: qInitial(1, d, s, 100), src: 50000, dst: 443,
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "v1 Initial coalesced with a Handshake", src: 443, dst: 50000,
			payload: append(qInitial(1, s, d, 90), qSized(1, 2, s, d, 40)...),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Initial,Handshake", QUICDCID: "090a0b0c", QUICSCID: "0102030405060708"},
		},
		{
			name: "three packets in a datagram: Initial, 0-RTT, Handshake", src: 50000, dst: 443,
			payload: bytes.Join([][]byte{qInitial(1, d, s, 30), qSized(1, 1, d, s, 20), qSized(1, 2, d, s, 10)}, nil),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Initial,0-RTT,Handshake", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "a short header packet coalesced at the end is not listed", src: 50000, dst: 443,
			payload: append(qInitial(1, d, s, 30), 0x41, 1, 2, 3, 4, 5, 6, 7, 8, 9),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "v1 Retry: the type bits are 3", src: 443, dst: 50000,
			payload: qLong(1, 3, s, d, bytes.Repeat([]byte{0xcc}, 40)),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Retry", QUICDCID: "090a0b0c", QUICSCID: "0102030405060708"},
		},
		{
			name: "v2 numbers the types differently: Retry is 0", src: 443, dst: 50000,
			payload: qLong(models.QUICVersion2, 0, s, d, bytes.Repeat([]byte{0xcc}, 40)),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: models.QUICVersion2, QUICPacketTypes: "Retry", QUICDCID: "090a0b0c", QUICSCID: "0102030405060708"},
		},
		{
			name: "v2 Initial (1), 0-RTT (2) and Handshake (3)", src: 50000, dst: 443,
			payload: bytes.Join([][]byte{qInitial(models.QUICVersion2, d, s, 30), qSized(models.QUICVersion2, 2, d, s, 20), qSized(models.QUICVersion2, 3, d, s, 10)}, nil),
			want:    models.PacketInfo{QUICLongHeader: true, QUICVersion: models.QUICVersion2, QUICPacketTypes: "Initial,0-RTT,Handshake", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "a draft version", src: 50000, dst: 443, payload: qInitial(draft29, d, s, 50),
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: draft29, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "Version Negotiation: no fixed bit, a list of versions", src: 443, dst: 50000,
			payload: qVersionNeg(s, d, 1, models.QUICVersion2, draft29),
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: 0, QUICPacketTypes: "Version Negotiation", QUICDCID: "090a0b0c", QUICSCID: "0102030405060708",
				QUICOfferedVersions: []uint32{1, models.QUICVersion2, draft29}},
		},
		{
			name: "Version Negotiation may echo long connection IDs", src: 443, dst: 50000,
			payload: qVersionNeg(bytes.Repeat([]byte{7}, 200), d, 1),
			want: models.PacketInfo{QUICLongHeader: true, QUICPacketTypes: "Version Negotiation", QUICDCID: hexOf(bytes.Repeat([]byte{7}, 200)), QUICSCID: "0102030405060708",
				QUICOfferedVersions: []uint32{1}},
		},
		{
			name: "an unknown version is accepted on port 443", src: 50000, dst: 443, payload: qInitial(0xdeadbeef, d, s, 20),
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: 0xdeadbeef, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "a greased version is accepted on port 443", src: 50000, dst: 443, payload: qInitial(0x1a2a3a4a, d, s, 20),
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: 0x1a2a3a4a, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{
			name: "DNS over QUIC on port 853 with a known version", src: 50000, dst: 853, payload: qInitial(1, d, s, 20),
			want: models.PacketInfo{QUICLongHeader: true, QUICVersion: 1, QUICPacketTypes: "Initial", QUICDCID: "0102030405060708", QUICSCID: "090a0b0c"},
		},
		{name: "an unknown version on another port is not QUIC", src: 50000, dst: 8000, payload: qInitial(0xdeadbeef, d, s, 20)},
		{name: "Version Negotiation is only accepted on port 443", src: 8000, dst: 50000, payload: qVersionNeg(s, d, 1)},
		{name: "Version Negotiation offering no known version is not QUIC", src: 443, dst: 50000, payload: qVersionNeg(s, d, 0x0d4a6f68, 0x616e6e65)},
		{name: "Version Negotiation offering nothing", src: 443, dst: 50000, payload: qVersionNeg(s, d)},
		{name: "Version Negotiation with a partial version at the end", src: 443, dst: 50000, payload: append(qVersionNeg(s, d, 1), 0x00, 0x01)},
		{
			name: "Version Negotiation offering a draft among unknown versions", src: 443, dst: 50000, payload: qVersionNeg(s, d, 0xdeadbeef, draft29),
			want: models.PacketInfo{QUICLongHeader: true, QUICPacketTypes: "Version Negotiation", QUICDCID: "090a0b0c", QUICSCID: "0102030405060708", QUICOfferedVersions: []uint32{0xdeadbeef, draft29}},
		},

		// not a long header, or not valid
		{name: "a short header (the header form bit is clear)", src: 50000, dst: 443, payload: append([]byte{0x40}, bytes.Repeat([]byte{1}, 30)...)},
		{name: "the fixed bit is clear in a versioned packet", src: 50000, dst: 443, payload: func() []byte { p := qInitial(1, d, s, 20); p[0] &^= 0x40; return p }()},
		{name: "a connection ID longer than 20 bytes", src: 50000, dst: 443, payload: qLong(1, 0, bytes.Repeat([]byte{1}, 21), s, qVarint(0), qVarint(0))},
		{name: "cut inside the destination connection ID", src: 50000, dst: 443, payload: qInitial(1, d, s, 20)[:9]},
		{name: "cut inside the source connection ID", src: 50000, dst: 443, payload: qInitial(1, d, s, 20)[:14]},
		{name: "DTLS application data on port 443", src: 50000, dst: 443, payload: []byte{0x17, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4, 5}},
		{name: "too short", src: 50000, dst: 443, payload: []byte{0xc0, 0, 0, 0, 1}},
		{name: "empty", src: 50000, dst: 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got models.PacketInfo
			fillQUIC(&got, tt.payload, tt.src, tt.dst)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFillQUICCoalescingLimits(t *testing.T) {
	d, s := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12}

	t.Run("a coalesced packet of another version ends the list", func(t *testing.T) {
		var got models.PacketInfo
		fillQUIC(&got, append(qInitial(1, d, s, 20), qSized(models.QUICVersion2, 3, d, s, 10)...), 50000, 443)
		assert.Equal(t, "Initial", got.QUICPacketTypes)
	})
	t.Run("a length that runs past the datagram ends the list", func(t *testing.T) {
		// the datagram was cut by the snap length: the Initial claims 500 bytes, 20 are there
		p := qLong(1, 0, d, s, qVarint(0), qVarint(500), bytes.Repeat([]byte{1}, 20))
		var got models.PacketInfo
		fillQUIC(&got, p, 50000, 443)
		assert.Equal(t, "Initial", got.QUICPacketTypes)
		assert.True(t, got.QUICLongHeader)
	})
	t.Run("an Initial cut before its token is still an Initial", func(t *testing.T) {
		var got models.PacketInfo
		fillQUIC(&got, qLong(1, 0, d, s, []byte{0x00}), 50000, 443)
		assert.Equal(t, "Initial", got.QUICPacketTypes)
	})
	t.Run("an Initial with a token", func(t *testing.T) {
		p := qLong(1, 0, d, s, qVarint(16), bytes.Repeat([]byte{9}, 16), qVarint(20), bytes.Repeat([]byte{1}, 20))
		p = append(p, qSized(1, 2, d, s, 10)...)
		var got models.PacketInfo
		fillQUIC(&got, p, 50000, 443)
		assert.Equal(t, "Initial,Handshake", got.QUICPacketTypes, "the token is skipped to find the next packet")
	})
	t.Run("at most eight packets are listed", func(t *testing.T) {
		var p []byte
		for i := 0; i < 12; i++ {
			p = append(p, qSized(1, 2, d, s, 5)...)
		}
		var got models.PacketInfo
		fillQUIC(&got, p, 50000, 443)
		assert.Equal(t, 8, bytes.Count([]byte(got.QUICPacketTypes), []byte("Handshake")))
	})
	t.Run("at most 64 offered versions are read", func(t *testing.T) {
		offered := make([]uint32, 200)
		offered[0] = 1
		var got models.PacketInfo
		fillQUIC(&got, qVersionNeg(d, s, offered...), 443, 50000)
		assert.Len(t, got.QUICOfferedVersions, quicMaxOffered)
	})
}

func TestQUICVarint(t *testing.T) {
	tests := []struct {
		in     []byte
		want   uint64
		n      int
		wantOK bool
	}{
		{[]byte{0x25}, 37, 1, true},
		{[]byte{0x7b, 0xbd}, 15293, 2, true},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, 4, true},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, 8, true}, // RFC 9000, appendix A.1
		{[]byte{0x40, 0x25}, 37, 2, true},                                                     // a longer encoding than needed is valid
		{[]byte{0x7b}, 0, 0, false},                                                           // cut short
		{nil, 0, 0, false},
	}
	for _, tt := range tests {
		v, n, ok := quicVarint(tt.in)
		assert.Equal(t, tt.wantOK, ok, "%x", tt.in)
		if ok {
			assert.Equal(t, tt.want, v, "%x", tt.in)
			assert.Equal(t, tt.n, n, "%x", tt.in)
		}
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
