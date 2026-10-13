package pcap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

// bootp builds a BOOTP/DHCP message: the fixed header for a client with
// hardware address 02:00:00:00:00:01, the magic cookie and the options.
func bootp(op byte, xid uint32, opts ...byte) []byte {
	b := make([]byte, 236)
	b[0], b[1], b[2] = op, 1, 6
	b[4], b[5], b[6], b[7] = byte(xid>>24), byte(xid>>16), byte(xid>>8), byte(xid)
	copy(b[12:], []byte{10, 0, 0, 5})      // ciaddr
	copy(b[16:], []byte{10, 0, 0, 6})      // yiaddr
	copy(b[20:], []byte{10, 0, 0, 1})      // siaddr
	copy(b[28:], []byte{2, 0, 0, 0, 0, 1}) // chaddr
	b = append(b, 0x63, 0x82, 0x53, 0x63)
	return append(b, opts...)
}

func TestParseDHCP(t *testing.T) {
	full := []byte{
		53, 1, 5, // Ack
		54, 4, 10, 0, 0, 1, // server identifier
		1, 4, 255, 255, 255, 0, // subnet mask
		3, 8, 10, 0, 0, 1, 10, 0, 0, 2, // routers: the first is kept
		6, 8, 8, 8, 8, 8, 1, 1, 1, 1, // DNS servers
		51, 4, 0, 0, 0x0e, 0x10, // lease time: 3600
		56, 5, 'h', 'e', 'l', 'l', 'o',
		0, 0, // padding
		255,
	}
	tests := []struct {
		name string
		msg  []byte
		want *models.DHCPInfo
	}{
		{"a full Ack", bootp(2, 0xdeadbeef, full...), &models.DHCPInfo{
			MsgType: 5, XID: 0xdeadbeef, ClientMAC: "02:00:00:00:00:01", ClientIP: "10.0.0.5", YourIP: "10.0.0.6", NextServerIP: "10.0.0.1",
			ServerID: "10.0.0.1", SubnetMask: "255.255.255.0", Router: "10.0.0.1", DNS: "8.8.8.8,1.1.1.1", LeaseSeconds: 3600, Message: "hello"}},
		{"each message type", bootp(1, 1, 53, 1, 1, 255), &models.DHCPInfo{MsgType: 1, XID: 1, ClientMAC: "02:00:00:00:00:01", ClientIP: "10.0.0.5", YourIP: "10.0.0.6", NextServerIP: "10.0.0.1"}},
		{"a type with no end option", bootp(1, 1, 53, 1, 8), &models.DHCPInfo{MsgType: 8, XID: 1, ClientMAC: "02:00:00:00:00:01", ClientIP: "10.0.0.5", YourIP: "10.0.0.6", NextServerIP: "10.0.0.1"}},
		{"an option that runs past the end is ignored", bootp(1, 1, 53, 1, 3, 56, 9, 'x'), &models.DHCPInfo{MsgType: 3, XID: 1, ClientMAC: "02:00:00:00:00:01", ClientIP: "10.0.0.5", YourIP: "10.0.0.6", NextServerIP: "10.0.0.1"}},
		{"the message type may follow other options", bootp(1, 1, 61, 2, 1, 2, 53, 1, 7), &models.DHCPInfo{MsgType: 7, XID: 1, ClientMAC: "02:00:00:00:00:01", ClientIP: "10.0.0.5", YourIP: "10.0.0.6", NextServerIP: "10.0.0.1"}},
		{"no message type option: BOOTP, not DHCP", bootp(1, 1, 255), nil},
		{"message type 0", bootp(1, 1, 53, 1, 0, 255), nil},
		{"message type 9", bootp(1, 1, 53, 1, 9, 255), nil},
		{"a message type option of the wrong length", bootp(1, 1, 53, 2, 1, 1, 255), nil},
		{"op that is neither request nor reply", bootp(3, 1, 53, 1, 1, 255), nil},
		{"no magic cookie", append(append([]byte{1, 1, 6}, make([]byte, 233)...), 53, 1, 1, 255), nil},
		{"shorter than the header", make([]byte, 100), nil},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseDHCP(tt.msg)
			if tt.want == nil {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, *tt.want, got)
		})
	}
}

func TestFillDHCP(t *testing.T) {
	msg := bootp(1, 7, 53, 1, 1, 255)
	tests := []struct {
		name             string
		srcPort, dstPort uint16
		payload          []byte
		want             bool
	}{
		{"client to server", 68, 67, msg, true},
		{"server to client", 67, 68, msg, true},
		{"relay to server", 67, 67, msg, true},
		{"other ports", 40000, 40001, msg, false},
		{"DHCPv6 ports", 546, 547, msg, false},
		{"a DHCP port but not a DHCP message", 68, 67, []byte("hello there"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var info models.PacketInfo
			fillDHCP(&info, tt.payload, tt.srcPort, tt.dstPort)
			assert.Equal(t, tt.want, info.DHCP != nil)
			if tt.want {
				assert.Equal(t, 1, info.DHCP.MsgType)
				assert.Equal(t, uint32(7), info.DHCP.XID)
			}
		})
	}
}

func TestDHCPOnRealCapture(t *testing.T) {
	packets, err := ReadPackets("../../testdata/IPv4-DHCP-Sequence.pcap")
	require.NoError(t, err)
	require.Len(t, packets, 4)
	var types []int
	for _, p := range packets {
		require.NotNil(t, p.DHCP)
		assert.Equal(t, "00:0b:82:01:fc:42", p.DHCP.ClientMAC)
		types = append(types, p.DHCP.MsgType)
	}
	assert.Equal(t, []int{1, 2, 3, 5}, types, "Discover, Offer, Request, Ack")
	assert.Equal(t, "192.168.0.10", packets[1].DHCP.YourIP)
}
