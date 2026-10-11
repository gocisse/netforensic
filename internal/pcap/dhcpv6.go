package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// DHCPv6 ports: clients listen on 546, servers and relay agents on 547.
const (
	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
)

// DHCPv6 message types (RFC 8415).
const (
	dhcpv6RelayForward = 12
	dhcpv6RelayReply   = 13
	dhcpv6MaxType      = 13
)

// DHCPv6 option codes.
const (
	dhcpv6OptClientID = 1
	dhcpv6OptServerID = 2
	dhcpv6OptIANA     = 3
	dhcpv6OptIATA     = 4
	dhcpv6OptIAAddr   = 5
	dhcpv6OptElapsed  = 8
	dhcpv6OptRelayMsg = 9
	dhcpv6OptStatus   = 13
	dhcpv6OptIAPD     = 25
	dhcpv6OptIAPrefix = 26
)

// Limits on what is read from a message.
const (
	dhcpv6MaxRelayDepth  = 8   // relay agents a message may pass through
	dhcpv6MaxOptionDepth = 4   // options nested in options (IA_NA > IAADDR > Status Code)
	dhcpv6MaxDUID        = 130 // the longest DUID, in bytes
)

// dhcpv6Msg is what is read from one DHCPv6 message.
type dhcpv6Msg struct {
	msgType    int
	xid        uint32
	clientID   string
	serverID   string
	ias        []string
	elapsed    uint16
	statusCode int
	statusMsg  string

	innerType int // for a relay message: the type of the message inside it
	relayed   bool

	wellFormed bool // the options ran exactly to the end of the message
}

// fillDHCPv6 sets the DHCPv6 fields on info if payload, sent from srcPort to
// dstPort over UDP, is a DHCPv6 message.
//
// On the DHCPv6 ports (546, 547) a message is accepted if it starts with a
// valid message type and is long enough to hold its header. On any other port
// it must also be well formed, with its options running exactly to the end,
// and carry a Client Identifier (or, for a relay message, a Relay Message), so
// that ordinary UDP payloads are not taken for DHCPv6.
func fillDHCPv6(info *models.PacketInfo, payload []byte, srcPort, dstPort uint16) {
	onPort := srcPort == dhcpv6ClientPort || srcPort == dhcpv6ServerPort || dstPort == dhcpv6ClientPort || dstPort == dhcpv6ServerPort
	m, ok := parseDHCPv6(payload, 0)
	if !ok {
		return
	}
	if !onPort && !(m.wellFormed && (m.relayed || m.clientID != "")) {
		return
	}
	info.DHCPv6MsgType = m.msgType
	info.DHCPv6InnerType = m.innerType
	info.DHCPv6XID = m.xid
	info.DHCPv6ClientID = m.clientID
	info.DHCPv6ServerID = m.serverID
	info.DHCPv6IAs = strings.Join(m.ias, ",")
	info.DHCPv6Elapsed = m.elapsed
	info.DHCPv6StatusCode = m.statusCode
	info.DHCPv6StatusMsg = m.statusMsg
}

// parseDHCPv6 reads a client/server or relay message. Options it cannot read
// are skipped over as far as the framing allows; wellFormed says whether all
// of them could be. It reports false if p is not a DHCPv6 message at all.
func parseDHCPv6(p []byte, depth int) (dhcpv6Msg, bool) {
	var m dhcpv6Msg
	if len(p) < 4 || p[0] == 0 || p[0] > dhcpv6MaxType {
		return m, false
	}
	m.msgType = int(p[0])
	m.innerType = m.msgType

	var opts []byte
	switch m.msgType {
	case dhcpv6RelayForward, dhcpv6RelayReply:
		// type, hop count, link address (16), peer address (16), options
		if len(p) < 34 || p[1] > 32 {
			return m, false
		}
		opts = p[34:]
	default:
		m.xid = uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
		opts = p[4:]
	}

	m.wellFormed = m.readOptions(opts, 0, depth, true)
	return m, true
}

// readOptions walks the options in b, depth levels down from the message's
// own. top says that b holds the message's options, as opposed to those
// nested in an IA option. It reports whether the options were framed
// correctly to the end of b.
func (m *dhcpv6Msg) readOptions(b []byte, level, relayDepth int, top bool) bool {
	for len(b) > 0 {
		if len(b) < 4 {
			return false
		}
		code, n := int(binary.BigEndian.Uint16(b)), int(binary.BigEndian.Uint16(b[2:]))
		if 4+n > len(b) {
			return false
		}
		val := b[4 : 4+n]
		b = b[4+n:]

		switch code {
		case dhcpv6OptClientID:
			if top && m.clientID == "" {
				m.clientID = duidString(val)
			}
		case dhcpv6OptServerID:
			if top && m.serverID == "" {
				m.serverID = duidString(val)
			}
		case dhcpv6OptElapsed:
			if top && len(val) >= 2 {
				m.elapsed = binary.BigEndian.Uint16(val)
			}
		case dhcpv6OptStatus:
			if len(val) >= 2 {
				if c := int(binary.BigEndian.Uint16(val)); c != 0 && m.statusCode == 0 {
					m.statusCode, m.statusMsg = c, cleanMeta(string(val[2:]))
				}
			}
		case dhcpv6OptIANA, dhcpv6OptIAPD: // IAID, T1, T2, options
			if top {
				m.noteIA(code)
			}
			if len(val) >= 12 && level < dhcpv6MaxOptionDepth {
				m.readOptions(val[12:], level+1, relayDepth, false)
			}
		case dhcpv6OptIATA: // IAID, options
			if top {
				m.noteIA(code)
			}
			if len(val) >= 4 && level < dhcpv6MaxOptionDepth {
				m.readOptions(val[4:], level+1, relayDepth, false)
			}
		case dhcpv6OptIAAddr: // address, preferred and valid lifetimes, options
			if len(val) >= 24 && level < dhcpv6MaxOptionDepth {
				m.readOptions(val[24:], level+1, relayDepth, false)
			}
		case dhcpv6OptIAPrefix: // lifetimes, prefix length, prefix, options
			if len(val) >= 25 && level < dhcpv6MaxOptionDepth {
				m.readOptions(val[25:], level+1, relayDepth, false)
			}
		case dhcpv6OptRelayMsg:
			if top && (m.msgType == dhcpv6RelayForward || m.msgType == dhcpv6RelayReply) && !m.relayed && relayDepth < dhcpv6MaxRelayDepth {
				if inner, ok := parseDHCPv6(val, relayDepth+1); ok {
					m.relayed = true
					m.innerType, m.xid = inner.innerType, inner.xid
					m.clientID, m.serverID = inner.clientID, inner.serverID
					m.ias, m.elapsed = inner.ias, inner.elapsed
					m.statusCode, m.statusMsg = inner.statusCode, inner.statusMsg
				}
			}
		}
	}
	return true
}

// noteIA records that the message holds an identity association of this kind.
func (m *dhcpv6Msg) noteIA(code int) {
	name := map[int]string{dhcpv6OptIANA: "IA_NA", dhcpv6OptIATA: "IA_TA", dhcpv6OptIAPD: "IA_PD"}[code]
	for _, have := range m.ias {
		if have == name {
			return
		}
	}
	m.ias = append(m.ias, name)
}

// duidString renders a DUID as lowercase hex, cut after a sane length.
func duidString(b []byte) string {
	if len(b) > dhcpv6MaxDUID {
		b = b[:dhcpv6MaxDUID]
	}
	return hex.EncodeToString(b)
}
