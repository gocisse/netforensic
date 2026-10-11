package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// quicPort is the port QUIC servers (HTTP/3) listen on.
const quicPort = 443

// QUIC long header packet types, by name.
const (
	quicInitial    = "Initial"
	quicZeroRTT    = "0-RTT"
	quicHandshake  = "Handshake"
	quicRetry      = "Retry"
	quicVersionNeg = "Version Negotiation"
)

// Limits on what is read from a datagram.
const (
	quicMaxCID       = 20 // the longest connection ID in the versions known here
	quicMaxCoalesced = 8  // packets read from one datagram
	quicMaxOffered   = 64 // versions read from a Version Negotiation packet
)

// fillQUIC sets the QUIC fields on info if payload, sent from srcPort to
// dstPort over UDP, starts with a QUIC long header (RFC 9000, section 17.2):
// the header form bit set and, except in a Version Negotiation packet, the
// fixed bit too.
//
// On port 443 any version is accepted. Elsewhere (DNS over QUIC uses 853, and
// HTTP/3 servers listen on other ports) only a known version is, so that
// ordinary UDP payloads that happen to start with a high bit are not taken for
// QUIC. A Version Negotiation packet, whose version field is just zero and
// which has no fixed bit to check, is only accepted on port 443, and only if
// it offers at least one version that is known (every real server offers v1
// or a draft): RTP and other protocols also start with a high bit. Datagrams that coalesce several packets (an Initial followed by a
// Handshake, say) list all of their types.
func fillQUIC(info *models.PacketInfo, payload []byte, srcPort, dstPort uint16) {
	h, ok := parseQUICLong(payload)
	if !ok {
		return
	}
	onPort := srcPort == quicPort || dstPort == quicPort
	if !onPort && (h.version == models.QUICVersionNegotiation || !knownQUICVersion(h.version)) {
		return
	}
	if h.version == models.QUICVersionNegotiation && !offersKnownVersion(h.offered) {
		return // other traffic that happens to start with a high bit and four zero bytes
	}
	info.QUICLongHeader = true
	info.QUICVersion = h.version
	info.QUICDCID, info.QUICSCID = h.dcid, h.scid
	info.QUICOfferedVersions = h.offered

	types := []string{h.typeName}
	rest := h.next
	for len(types) < quicMaxCoalesced && len(rest) >= 7 {
		n, ok := parseQUICLong(rest)
		if !ok || n.version != h.version {
			break
		}
		types = append(types, n.typeName)
		rest = n.next
	}
	info.QUICPacketTypes = strings.Join(types, ",")
}

// knownQUICVersion reports whether v is a version this tool recognizes: v1,
// v2, a draft, or Version Negotiation.
func knownQUICVersion(v uint32) bool {
	_, draft := models.QUICDraft(v)
	return draft || v == models.QUICVersionNegotiation || v == models.QUICVersion1 || v == models.QUICVersion2
}

// offersKnownVersion reports whether any of vs is a version known here.
func offersKnownVersion(vs []uint32) bool {
	for _, v := range vs {
		if v != models.QUICVersionNegotiation && knownQUICVersion(v) {
			return true
		}
	}
	return false
}

// quicHeader is what is read from one long header packet.
type quicHeader struct {
	version  uint32
	typeName string
	dcid     string
	scid     string
	offered  []uint32 // Version Negotiation: the versions the server supports
	next     []byte   // what follows this packet in the datagram, if it can be told
}

// parseQUICLong reads a long header packet at the start of b.
func parseQUICLong(b []byte) (quicHeader, bool) {
	var h quicHeader
	if len(b) < 7 || b[0]&0x80 == 0 { // header form: 1 is a long header
		return h, false
	}
	h.version = binary.BigEndian.Uint32(b[1:5])
	if h.version != models.QUICVersionNegotiation && b[0]&0x40 == 0 { // the fixed bit
		return h, false
	}

	dcidLen := int(b[5])
	maxCID := quicMaxCID
	if h.version == models.QUICVersionNegotiation {
		maxCID = 255 // a server may echo any length the client sent
	}
	if dcidLen > maxCID || len(b) < 6+dcidLen+1 {
		return h, false
	}
	h.dcid = hex.EncodeToString(b[6 : 6+dcidLen])
	scidLen := int(b[6+dcidLen])
	if scidLen > maxCID || len(b) < 7+dcidLen+scidLen {
		return h, false
	}
	h.scid = hex.EncodeToString(b[7+dcidLen : 7+dcidLen+scidLen])
	rest := b[7+dcidLen+scidLen:]

	if h.version == models.QUICVersionNegotiation {
		h.typeName = quicVersionNeg
		if len(rest) == 0 || len(rest)%4 != 0 {
			return h, false // the list of versions runs to the end of the datagram, 4 bytes each
		}
		for len(rest) >= 4 && len(h.offered) < quicMaxOffered {
			h.offered = append(h.offered, binary.BigEndian.Uint32(rest))
			rest = rest[4:]
		}
		return h, true
	}

	typ := quicPacketType(h.version, (b[0]>>4)&0x03)
	h.typeName = typ
	switch typ {
	case quicRetry:
		return h, true // a retry token and an integrity tag run to the end
	case quicInitial:
		tokenLen, n, ok := quicVarint(rest)
		if !ok || uint64(len(rest)-n) < tokenLen {
			return h, true
		}
		rest = rest[n+int(tokenLen):]
		fallthrough
	case quicZeroRTT, quicHandshake:
		length, n, ok := quicVarint(rest)
		if !ok || uint64(len(rest)-n) < length {
			return h, true // cut short by the snap length, or the last packet
		}
		h.next = rest[n+int(length):]
	}
	return h, true
}

// quicPacketType names the long header packet type bits for a version. v2
// (RFC 9369) numbers them differently from v1 and the drafts.
func quicPacketType(version uint32, bits byte) string {
	if version == models.QUICVersion2 {
		return [4]string{quicRetry, quicInitial, quicZeroRTT, quicHandshake}[bits]
	}
	return [4]string{quicInitial, quicZeroRTT, quicHandshake, quicRetry}[bits]
}

// quicVarint reads a QUIC variable-length integer (RFC 9000, section 16): the
// top two bits of the first byte give the length, 1, 2, 4 or 8 bytes.
func quicVarint(b []byte) (value uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	value = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		value = value<<8 | uint64(b[i])
	}
	return value, n, true
}
