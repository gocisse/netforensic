// Package pcap implements the pcap reading layer.
package pcap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gocisse/netforensic/internal/models"
)

// TruncatedError reports that a capture file ended in the middle of a
// record. ReadPackets returns it together with the packets that were read
// successfully before the cut, so callers can analyze the partial capture:
//
//	packets, err := ReadPackets(path)
//	var trunc *TruncatedError
//	if errors.As(err, &trunc) { /* use packets, warn the user */ }
type TruncatedError struct {
	Packets int   // packets read before the file ended
	Err     error // underlying read error
}

// Error implements error.
func (e *TruncatedError) Error() string {
	return fmt.Sprintf("capture file ended unexpectedly after %d packets: %v", e.Packets, e.Err)
}

// Unwrap returns the underlying read error.
func (e *TruncatedError) Unwrap() error { return e.Err }

// ReadPackets opens the pcap or pcapng file at filePath and returns a
// simplified view of every packet it contains. Packets without an IP or ARP
// layer are skipped. If the file is cut off mid-record, the packets read so
// far are returned together with a *TruncatedError.
func ReadPackets(filePath string) ([]models.PacketInfo, error) {
	return ReadPacketsWithOptions(filePath, ReadOptions{})
}

// ReadOptions tunes ReadPacketsWithOptions.
type ReadOptions struct {
	// FullPayload keeps the complete TCP/UDP payload of every packet in
	// PacketInfo.Payload (needed to reconstruct streams), at the cost of
	// memory proportional to the capture size.
	FullPayload bool
}

// ReadPacketsWithOptions is ReadPackets with explicit options.
func ReadPacketsWithOptions(filePath string, opts ReadOptions) ([]models.PacketInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer f.Close()

	src, err := newSource(f)
	if err != nil {
		return nil, err
	}

	var packets []models.PacketInfo
	for {
		data, ci, err := src.ReadPacketData()
		if errors.Is(err, io.EOF) && !src.cutShort() {
			break
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// The file was cut off mid-record, as happens with ring buffers
			// and crashed captures. Keep what was read.
			models.AssignConnections(packets)
			annotateHandshakes(packets)
			return packets, &TruncatedError{Packets: len(packets), Err: err}
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}

		pkt := gopacket.NewPacket(data, src.linkType(ci), gopacket.NoCopy)
		info, ok := packetInfo(pkt)
		if !ok {
			continue
		}
		if opts.FullPayload {
			info.Payload = fullPayload(pkt)
		}
		info.Timestamp = ci.Timestamp
		info.Size = ci.Length
		packets = append(packets, info)
	}
	models.AssignConnections(packets)
	annotateHandshakes(packets)
	return packets, nil
}

// packetInfo extracts addressing and protocol details from a decoded packet.
// It reports false if the packet has no IPv4 or IPv6 layer.
func packetInfo(pkt gopacket.Packet) (models.PacketInfo, bool) {
	var info models.PacketInfo

	if l := pkt.Layer(layers.LayerTypeARP); l != nil {
		fillARP(&info, l.(*layers.ARP))
		return info, true
	}

	switch {
	case pkt.Layer(layers.LayerTypeIPv4) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		info.SrcIP, info.DstIP = ip.SrcIP.String(), ip.DstIP.String()
	case pkt.Layer(layers.LayerTypeIPv6) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		info.SrcIP, info.DstIP = ip.SrcIP.String(), ip.DstIP.String()
	default:
		return info, false
	}

	switch {
	case pkt.Layer(layers.LayerTypeTCP) != nil:
		t := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		info.Protocol = models.ProtocolTCP
		info.SrcPort, info.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		info.PayloadSize = tcpPayloadLen(pkt, t)
		info.PayloadPreview = previewPayload(t.Payload)
		info.TCPSeq = t.Seq
		info.TCPFlags = tcpFlags(t)
		info.TCPAck = t.Ack
		info.TCPWindow = uint32(t.Window)
		fillHTTP(&info, t.Payload)
		fillTLS(&info, t.Payload)
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		u := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		info.Protocol = models.ProtocolUDP
		info.SrcPort, info.DstPort = uint16(u.SrcPort), uint16(u.DstPort)
		info.PayloadSize = len(u.Payload)
		info.PayloadPreview = previewPayload(u.Payload)
	case pkt.Layer(layers.LayerTypeICMPv4) != nil:
		ic := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		info.Protocol = models.ProtocolICMP
		info.ICMPType, info.ICMPCode = ic.TypeCode.Type(), ic.TypeCode.Code()
		info.ICMPMessage = icmpMessage(info.ICMPType, info.ICMPCode)
	case pkt.Layer(layers.LayerTypeICMPv6) != nil:
		info.Protocol = models.ProtocolICMP
	}
	if l := pkt.Layer(layers.LayerTypeDNS); l != nil {
		fillDNS(&info, l.(*layers.DNS))
	}
	return info, true
}

// fillDNS copies DNS message details into info. Messages without a question
// are ignored.
func fillDNS(info *models.PacketInfo, d *layers.DNS) {
	if len(d.Questions) == 0 {
		return
	}
	q := d.Questions[0]
	info.DNSID = d.ID
	info.DNSQueryName = string(q.Name)
	info.DNSIsQuery = !d.QR
	info.DNSResponseType = q.Type.String()
	if d.QR {
		for _, a := range d.Answers {
			info.DNSAnswers = append(info.DNSAnswers, dnsAnswer(a))
		}
		info.DNSResponseCode = dnsResponseCode(d.ResponseCode)
		if len(d.Answers) > 0 {
			info.DNSResponseType = d.Answers[0].Type.String()
		}
	}
}

// dnsResponseCode returns the conventional upper-case name of an RCODE.
func dnsResponseCode(c layers.DNSResponseCode) string {
	switch c {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", uint8(c))
}

// tcpFlags renders the set TCP flags as a comma-separated string such as "PSH,ACK".
func tcpFlags(t *layers.TCP) string {
	var flags []string
	for _, f := range []struct {
		set  bool
		name string
	}{
		{t.FIN, "FIN"}, {t.SYN, "SYN"}, {t.RST, "RST"}, {t.PSH, "PSH"},
		{t.ACK, "ACK"}, {t.URG, "URG"}, {t.ECE, "ECE"}, {t.CWR, "CWR"},
	} {
		if f.set {
			flags = append(flags, f.name)
		}
	}
	return strings.Join(flags, ",")
}

// fillARP sets the ARP fields on info. SrcIP and DstIP carry the sender and
// target protocol addresses so ARP packets fit the generic packet view.
func fillARP(info *models.PacketInfo, a *layers.ARP) {
	info.Protocol = models.ProtocolARP
	info.ARPOperation = "request"
	if a.Operation == layers.ARPReply {
		info.ARPOperation = "reply"
	}
	info.ARPSenderIP = net.IP(a.SourceProtAddress).String()
	info.ARPTargetIP = net.IP(a.DstProtAddress).String()
	info.ARPSenderMAC = net.HardwareAddr(a.SourceHwAddress).String()
	info.SrcIP, info.DstIP = info.ARPSenderIP, info.ARPTargetIP
}

var icmpTypeNames = map[uint8]string{
	0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect",
	8: "Echo Request", 9: "Router Advertisement", 10: "Router Solicitation",
	11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp Request", 14: "Timestamp Reply",
}

var icmpCodeNames = map[uint8]map[uint8]string{
	3: {0: "Network Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable", 3: "Port Unreachable",
		4: "Fragmentation Needed", 5: "Source Route Failed", 9: "Network Administratively Prohibited",
		10: "Host Administratively Prohibited", 13: "Communication Administratively Prohibited"},
	5:  {0: "Redirect for Network", 1: "Redirect for Host", 2: "Redirect for TOS and Network", 3: "Redirect for TOS and Host"},
	11: {0: "TTL Exceeded in Transit", 1: "Fragment Reassembly Time Exceeded"},
}

// icmpMessage returns a human-readable description of an ICMPv4 type and code.
func icmpMessage(typ, code uint8) string {
	name, ok := icmpTypeNames[typ]
	if !ok {
		return fmt.Sprintf("Type %d Code %d", typ, code)
	}
	if code == 0 && icmpCodeNames[typ] == nil {
		return name
	}
	if c, ok := icmpCodeNames[typ][code]; ok {
		return name + ": " + c
	}
	return fmt.Sprintf("%s: Code %d", name, code)
}

// maxPayloadPreview bounds the payload bytes kept per packet.
const maxPayloadPreview = 512

// fullPayload returns a copy of the whole TCP or UDP payload of pkt, or nil.
func fullPayload(pkt gopacket.Packet) []byte {
	var payload []byte
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		payload = l.(*layers.TCP).Payload
	} else if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		payload = l.(*layers.UDP).Payload
	}
	if len(payload) == 0 {
		return nil
	}
	return append([]byte(nil), payload...)
}

// previewPayload returns a copy of the first bytes of payload, or nil.
func previewPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) > maxPayloadPreview {
		payload = payload[:maxPayloadPreview]
	}
	return append([]byte(nil), payload...)
}

// dnsAnswer renders a resource record as "TYPE data".
func dnsAnswer(rr layers.DNSResourceRecord) string {
	typ := rr.Type.String()
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return typ + " " + rr.IP.String()
	case layers.DNSTypeCNAME:
		return typ + " " + string(rr.CNAME)
	case layers.DNSTypeNS:
		return typ + " " + string(rr.NS)
	case layers.DNSTypePTR:
		return typ + " " + string(rr.PTR)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%s %d %s", typ, rr.MX.Preference, rr.MX.Name)
	case layers.DNSTypeTXT:
		return typ + " " + strings.Join(txtStrings(rr.TXTs), " ")
	}
	return typ
}

func txtStrings(txts [][]byte) []string {
	out := make([]string, len(txts))
	for i, t := range txts {
		out[i] = string(t)
	}
	return out
}

// source reads packets from a capture file of either supported format.
type source interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	linkType(ci gopacket.CaptureInfo) layers.LinkType
	// cutShort reports, after an io.EOF, whether the file actually ended in
	// the middle of a record.
	cutShort() bool
}

type pcapSource struct{ *pcapgo.Reader }

// cutShort is always false: pcapgo reports a record cut short as
// io.ErrUnexpectedEOF, which ReadPackets handles directly.
func (s pcapSource) cutShort() bool { return false }

func (s pcapSource) linkType(gopacket.CaptureInfo) layers.LinkType { return s.LinkType() }

// ngSource reads pcapng, whose interfaces may each have their own link type.
type ngSource struct {
	*pcapgo.NgReader
	track *blockTracker
}

// cutShort reports whether the file ends inside a block. The pcapng reader
// returns a plain io.EOF there, so the framing is tracked separately.
func (s ngSource) cutShort() bool { return s.track.midBlock() }

func (s ngSource) linkType(ci gopacket.CaptureInfo) layers.LinkType {
	if iface, err := s.Interface(ci.InterfaceIndex); err == nil {
		return iface.LinkType
	}
	return layers.LinkTypeEthernet
}

// pcapngMagic is the block type of a pcapng section header block.
var pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

// newSource detects whether r is a pcap or pcapng file and opens it.
func newSource(r io.Reader) (source, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(len(pcapngMagic))
	if err != nil {
		return nil, fmt.Errorf("read capture header: %w", err)
	}
	if bytes.Equal(magic, pcapngMagic) {
		track := &blockTracker{r: br}
		ng, err := pcapgo.NewNgReader(track, pcapgo.NgReaderOptions{WantMixedLinkType: true})
		if err != nil {
			return nil, fmt.Errorf("read pcapng header: %w", err)
		}
		return ngSource{ng, track}, nil
	}
	pr, err := pcapgo.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("read pcap header: %w", err)
	}
	return pcapSource{pr}, nil
}

// tcpPayloadLen returns the TCP payload length the sender put on the wire,
// derived from the IP length so that captures truncated by a small snaplen
// still report the real segment size (sequence-number accounting depends on
// it). It falls back to the captured length when the IP length is unusable,
// for example with segmentation offload where it is recorded as 0.
func tcpPayloadLen(pkt gopacket.Packet, t *layers.TCP) int {
	captured := len(t.Payload)
	hdr := int(t.DataOffset) * 4

	var ipPayload int
	switch {
	case pkt.Layer(layers.LayerTypeIPv4) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip.Length == 0 {
			return captured
		}
		ipPayload = int(ip.Length) - int(ip.IHL)*4
	case pkt.Layer(layers.LayerTypeIPv6) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ip.Length == 0 {
			return captured
		}
		ipPayload = int(ip.Length)
	default:
		return captured
	}
	if n := ipPayload - hdr; n >= captured {
		return n
	}
	return captured
}
