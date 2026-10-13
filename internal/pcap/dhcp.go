package pcap

import (
	"encoding/binary"
	"net"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// DHCP (IPv4) ports: servers and relay agents listen on 67, clients on 68.
const (
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// The fixed BOOTP header is 236 bytes; the magic cookie follows it, then the
// options (RFC 2131, RFC 2132).
const (
	bootpHeaderLen = 236
	dhcpCookie     = 0x63825363
)

// DHCP option codes.
const (
	dhcpOptPad        = 0
	dhcpOptSubnetMask = 1
	dhcpOptRouter     = 3
	dhcpOptDNS        = 6
	dhcpOptLeaseTime  = 51
	dhcpOptMsgType    = 53
	dhcpOptServerID   = 54
	dhcpOptMessage    = 56
	dhcpOptEnd        = 255
)

// dhcpMaxType is the highest DHCP message type: 1 Discover, 2 Offer, 3
// Request, 4 Decline, 5 Ack, 6 Nak, 7 Release, 8 Inform.
const dhcpMaxType = 8

// fillDHCP sets info.DHCP if payload, sent from srcPort to dstPort over UDP,
// is a DHCP message: on a DHCP port (67 or 68), with the BOOTP header, the
// magic cookie and a DHCP Message Type option (53) holding a type from 1 to 8.
// A BOOTP message without them is not DHCP.
func fillDHCP(info *models.PacketInfo, payload []byte, srcPort, dstPort uint16) {
	isPort := func(p uint16) bool { return p == dhcpServerPort || p == dhcpClientPort }
	if !isPort(srcPort) && !isPort(dstPort) {
		return
	}
	if d, ok := parseDHCP(payload); ok {
		info.DHCP = &d
	}
}

// parseDHCP reads a DHCP message. It reports false if p is not one. Options
// that run past the end of the message are ignored.
func parseDHCP(p []byte) (models.DHCPInfo, bool) {
	var d models.DHCPInfo
	if len(p) < bootpHeaderLen+4 || (p[0] != 1 && p[0] != 2) || binary.BigEndian.Uint32(p[bootpHeaderLen:]) != dhcpCookie {
		return d, false
	}
	d.XID = binary.BigEndian.Uint32(p[4:])
	d.ClientIP = ipOrEmpty(p[12:16])
	d.YourIP = ipOrEmpty(p[16:20])
	d.NextServerIP = ipOrEmpty(p[20:24])
	if hlen := int(p[2]); p[1] == 1 && hlen == 6 { // Ethernet
		d.ClientMAC = net.HardwareAddr(p[28 : 28+hlen]).String()
	}

	b := p[bootpHeaderLen+4:]
	for len(b) > 0 {
		code := b[0]
		if code == dhcpOptEnd {
			break
		}
		if code == dhcpOptPad {
			b = b[1:]
			continue
		}
		if len(b) < 2 || 2+int(b[1]) > len(b) {
			break
		}
		val := b[2 : 2+int(b[1])]
		b = b[2+int(b[1]):]
		switch code {
		case dhcpOptMsgType:
			if len(val) == 1 {
				d.MsgType = int(val[0])
			}
		case dhcpOptSubnetMask:
			if len(val) == 4 {
				d.SubnetMask = net.IP(val).String()
			}
		case dhcpOptRouter:
			if len(val) >= 4 {
				d.Router = net.IP(val[:4]).String()
			}
		case dhcpOptDNS:
			var ips []string
			for i := 0; i+4 <= len(val) && len(ips) < 4; i += 4 {
				ips = append(ips, net.IP(val[i:i+4]).String())
			}
			d.DNS = strings.Join(ips, ",")
		case dhcpOptLeaseTime:
			if len(val) == 4 {
				d.LeaseSeconds = binary.BigEndian.Uint32(val)
			}
		case dhcpOptServerID:
			if len(val) == 4 {
				d.ServerID = net.IP(val).String()
			}
		case dhcpOptMessage:
			d.Message = cleanMeta(string(val))
		}
	}
	if d.MsgType < 1 || d.MsgType > dhcpMaxType {
		return models.DHCPInfo{}, false
	}
	return d, true
}

// ipOrEmpty writes a 4-byte address, or "" for 0.0.0.0.
func ipOrEmpty(b []byte) string {
	if b[0]|b[1]|b[2]|b[3] == 0 {
		return ""
	}
	return net.IP(b).String()
}
