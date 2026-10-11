package pcap

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

func d6opt(code uint16, val ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, code)
	b = binary.BigEndian.AppendUint16(b, uint16(len(val)))
	return append(b, val...)
}

func d6cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func d6status(code uint16, msg string) []byte {
	return d6opt(13, append(binary.BigEndian.AppendUint16(nil, code), msg...)...)
}

// d6ia builds an IA_NA/IA_PD option (IAID, T1, T2, options) or IA_TA (IAID, options).
func d6ia(code uint16, nested ...[]byte) []byte {
	hdr := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
	if code == 4 {
		hdr = hdr[:4]
	}
	return d6opt(code, append(hdr, d6cat(nested...)...)...)
}

func d6msg(typ byte, xid uint32, opts ...[]byte) []byte {
	b := []byte{typ, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	return append(b, d6cat(opts...)...)
}

func d6relay(typ byte, hops byte, inner []byte) []byte {
	b := append([]byte{typ, hops}, make([]byte, 32)...)
	return append(b, d6opt(9, inner...)...)
}

func TestFillDHCPv6(t *testing.T) {
	cid := d6opt(1, 0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
	sid := d6opt(2, 0, 1, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8)
	iaAddr := d6opt(5, append(make([]byte, 24), d6status(2, "none left")...)...) // address, lifetimes, then options

	tests := []struct {
		name        string
		payload     []byte
		src, dst    uint16
		want        models.PacketInfo
		wantNotDHCP bool
	}{
		{
			name:    "Solicit with client ID, IA_NA, IA_PD and elapsed time",
			payload: d6msg(1, 0xabcdef, cid, d6opt(8, 0x01, 0x2c), d6ia(3), d6ia(25)),
			src:     546, dst: 547,
			want: models.PacketInfo{DHCPv6MsgType: 1, DHCPv6InnerType: 1, DHCPv6XID: 0xabcdef, DHCPv6ClientID: "00030001aabbccddeeff",
				DHCPv6IAs: "IA_NA,IA_PD", DHCPv6Elapsed: 300},
		},
		{
			name:    "Reply with both identifiers and a top-level status",
			payload: d6msg(7, 0x000102, cid, sid, d6status(2, "No addresses available")),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 0x102, DHCPv6ClientID: "00030001aabbccddeeff",
				DHCPv6ServerID:   "00010001010203040506 0708"[:0] + "0001000101020304050607 08"[:0] + "000100010102030405060708",
				DHCPv6StatusCode: 2, DHCPv6StatusMsg: "No addresses available"},
		},
		{
			name:    "a status inside an IA_NA is found",
			payload: d6msg(7, 1, cid, sid, d6ia(3, d6status(2, "nothing"))),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff",
				DHCPv6ServerID: "000100010102030405060708", DHCPv6IAs: "IA_NA", DHCPv6StatusCode: 2, DHCPv6StatusMsg: "nothing"},
		},
		{
			name:    "a status inside an address inside an IA_NA",
			payload: d6msg(7, 1, cid, sid, d6ia(3, iaAddr)),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff",
				DHCPv6ServerID: "000100010102030405060708", DHCPv6IAs: "IA_NA", DHCPv6StatusCode: 2, DHCPv6StatusMsg: "none left"},
		},
		{
			name:    "a status inside an IA_PD prefix and an IA_TA",
			payload: d6msg(7, 1, cid, sid, d6ia(4), d6ia(25, d6opt(26, append(make([]byte, 25), d6status(6, "no prefix")...)...))),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff",
				DHCPv6ServerID: "000100010102030405060708", DHCPv6IAs: "IA_TA,IA_PD", DHCPv6StatusCode: 6, DHCPv6StatusMsg: "no prefix"},
		},
		{
			name:    "Success (0) is not recorded as a status",
			payload: d6msg(7, 1, cid, sid, d6status(0, "all good")),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff", DHCPv6ServerID: "000100010102030405060708"},
		},
		{
			name:    "the first non-zero status wins",
			payload: d6msg(7, 1, cid, sid, d6status(0, "ok"), d6status(3, "no binding"), d6status(2, "later")),
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff", DHCPv6ServerID: "000100010102030405060708",
				DHCPv6StatusCode: 3, DHCPv6StatusMsg: "no binding"},
		},
		{
			name:    "a relay-forward message carries the client's message",
			payload: d6relay(12, 1, d6msg(1, 0x3603eb, cid, d6ia(3))),
			src:     547, dst: 547,
			want: models.PacketInfo{DHCPv6MsgType: 12, DHCPv6InnerType: 1, DHCPv6XID: 0x3603eb, DHCPv6ClientID: "00030001aabbccddeeff", DHCPv6IAs: "IA_NA"},
		},
		{
			name:    "a relay-reply carries the server's message, through two relays",
			payload: d6relay(13, 1, d6relay(13, 0, d6msg(2, 9, cid, sid))),
			src:     547, dst: 547,
			want: models.PacketInfo{DHCPv6MsgType: 13, DHCPv6InnerType: 2, DHCPv6XID: 9, DHCPv6ClientID: "00030001aabbccddeeff", DHCPv6ServerID: "000100010102030405060708"},
		},
		{
			name:    "on a DHCPv6 port a short message is enough",
			payload: []byte{7, 0, 0, 1},
			src:     547, dst: 546,
			want: models.PacketInfo{DHCPv6MsgType: 7, DHCPv6InnerType: 7, DHCPv6XID: 1},
		},
		{
			name:    "on a DHCPv6 port damaged options are tolerated",
			payload: d6msg(1, 5, cid, []byte{0, 3, 0, 40, 1, 2}), // the IA_NA claims 40 bytes and has 2
			src:     546, dst: 547,
			want: models.PacketInfo{DHCPv6MsgType: 1, DHCPv6InnerType: 1, DHCPv6XID: 5, DHCPv6ClientID: "00030001aabbccddeeff"},
		},
		{
			name:    "off the DHCPv6 ports a well-formed message with a client ID is recognized",
			payload: d6msg(3, 0x777, cid, sid),
			src:     40000, dst: 40001,
			want: models.PacketInfo{DHCPv6MsgType: 3, DHCPv6InnerType: 3, DHCPv6XID: 0x777, DHCPv6ClientID: "00030001aabbccddeeff", DHCPv6ServerID: "000100010102030405060708"},
		},
		{
			name:    "off the ports a relay message with a relayed message is recognized",
			payload: d6relay(12, 0, d6msg(1, 1, cid)),
			src:     40000, dst: 40001,
			want: models.PacketInfo{DHCPv6MsgType: 12, DHCPv6InnerType: 1, DHCPv6XID: 1, DHCPv6ClientID: "00030001aabbccddeeff"},
		},
		{name: "off the ports damaged options are not DHCPv6", payload: d6msg(1, 5, cid, []byte{0, 3, 0, 40, 1, 2}), src: 40000, dst: 40001, wantNotDHCP: true},
		{name: "off the ports a message with no client ID is not DHCPv6", payload: d6msg(1, 5, sid), src: 40000, dst: 40001, wantNotDHCP: true},
		{name: "off the ports a short message is not DHCPv6", payload: []byte{7, 0, 0, 1}, src: 40000, dst: 40001, wantNotDHCP: true},
		{name: "off the ports a relay message with no relayed message is not DHCPv6", payload: d6relay(12, 0, []byte{99, 0, 0, 0}), src: 40000, dst: 40001, wantNotDHCP: true},
		{name: "type 0 is not a message type", payload: d6msg(0, 1, cid), src: 546, dst: 547, wantNotDHCP: true},
		{name: "type 14 is not a message type", payload: d6msg(14, 1, cid), src: 546, dst: 547, wantNotDHCP: true},
		{name: "a relay message too short for its header", payload: []byte{12, 0, 0, 0, 0}, src: 547, dst: 547, wantNotDHCP: true},
		{name: "a relay message with an absurd hop count", payload: append([]byte{12, 200}, make([]byte, 32)...), src: 547, dst: 547, wantNotDHCP: true},
		{name: "empty", payload: nil, src: 546, dst: 547, wantNotDHCP: true},
		{name: "three bytes", payload: []byte{1, 2, 3}, src: 546, dst: 547, wantNotDHCP: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got models.PacketInfo
			fillDHCPv6(&got, tt.payload, tt.src, tt.dst)
			if tt.wantNotDHCP {
				assert.Equal(t, models.PacketInfo{}, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFillDHCPv6Bounds(t *testing.T) {
	t.Run("a very long DUID is cut", func(t *testing.T) {
		var got models.PacketInfo
		fillDHCPv6(&got, d6msg(1, 1, d6opt(1, make([]byte, 1000)...)), 546, 547)
		assert.Len(t, got.DHCPv6ClientID, 2*dhcpv6MaxDUID)
	})
	t.Run("relays nested too deeply are not followed", func(t *testing.T) {
		inner := d6msg(1, 1, d6opt(1, 1, 2, 3))
		for i := 0; i < 20; i++ {
			inner = d6relay(12, 0, inner)
		}
		var got models.PacketInfo
		fillDHCPv6(&got, inner, 547, 547)
		assert.Equal(t, 12, got.DHCPv6MsgType)
		assert.Empty(t, got.DHCPv6ClientID, "gave up before the end")
	})
	t.Run("options nested too deeply are not followed", func(t *testing.T) {
		nest := d6status(2, "deep")
		for i := 0; i < 10; i++ {
			nest = d6ia(3, nest)
		}
		var got models.PacketInfo
		fillDHCPv6(&got, d6msg(7, 1, nest), 547, 546)
		assert.Equal(t, 7, got.DHCPv6MsgType)
		assert.Zero(t, got.DHCPv6StatusCode)
	})
	t.Run("a status message is cleaned", func(t *testing.T) {
		var got models.PacketInfo
		fillDHCPv6(&got, d6msg(7, 1, d6status(2, "bad\x1b[2Jnews")), 547, 546)
		assert.Equal(t, "bad [2Jnews", got.DHCPv6StatusMsg)
	})
	t.Run("a truncated status option is ignored", func(t *testing.T) {
		var got models.PacketInfo
		fillDHCPv6(&got, d6msg(7, 1, d6opt(13, 0)), 547, 546)
		assert.Zero(t, got.DHCPv6StatusCode)
	})
}
