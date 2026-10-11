// Package pcap implements the pcap reading layer.
package pcap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
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
	packets, _, err := ReadPacketsStats(filePath, ReadOptions{})
	return packets, err
}

// ReadOptions tunes ReadPacketsWithOptions.
type ReadOptions struct {
	// FullPayload keeps the complete TCP/UDP payload of every packet in
	// PacketInfo.Payload (needed to reconstruct streams), at the cost of
	// memory proportional to the capture size.
	FullPayload bool
}

// ReadStats accounts for every frame in a capture file, including the ones
// that did not become packets.
type ReadStats struct {
	Frames int // frames read from the file

	// SkippedUnsupportedLink counts frames whose link-layer type this tool
	// cannot decode (for example Ethernet mPackets, type 274), and
	// UnsupportedLinkTypes breaks them down by pcap link type number.
	SkippedUnsupportedLink int
	UnsupportedLinkTypes   map[int]int

	// SkippedNonIP counts frames that decoded but carry neither IP nor ARP,
	// such as spanning tree, LLDP or other layer-2 control traffic.
	SkippedNonIP int
}

// linkTypeNames names the unsupported link types that turn up in practice.
var linkTypeNames = map[int]string{
	274: "Ethernet mPacket",
}

// Describe says which frames were skipped, for example
// "10667 frames of unsupported link type 274 (Ethernet mPacket); 3 non-IP frames". It is empty
// if none were.
func (s ReadStats) Describe() string {
	var parts []string
	types := make([]int, 0, len(s.UnsupportedLinkTypes))
	for lt := range s.UnsupportedLinkTypes {
		types = append(types, lt)
	}
	sort.Ints(types)
	for _, lt := range types {
		name := ""
		if n, ok := linkTypeNames[lt]; ok {
			name = " (" + n + ")"
		}
		parts = append(parts, fmt.Sprintf("%d frames of unsupported link type %d%s", s.UnsupportedLinkTypes[lt], lt, name))
	}
	if s.SkippedNonIP > 0 {
		parts = append(parts, fmt.Sprintf("%d non-IP frames", s.SkippedNonIP))
	}
	return strings.Join(parts, "; ")
}

// Skipped returns the number of frames that were read but not analyzed.
func (s ReadStats) Skipped() int { return s.SkippedUnsupportedLink + s.SkippedNonIP }

// ReadPacketsWithOptions is ReadPackets with explicit options.
func ReadPacketsWithOptions(filePath string, opts ReadOptions) ([]models.PacketInfo, error) {
	packets, _, err := ReadPacketsStats(filePath, opts)
	return packets, err
}

// ReadPacketsStats is ReadPacketsWithOptions that also reports how many
// frames were skipped and why, so callers can say that the analysis does not
// cover the whole file. The stats are valid alongside a *TruncatedError.
func ReadPacketsStats(filePath string, opts ReadOptions) ([]models.PacketInfo, ReadStats, error) {
	var stats ReadStats
	f, err := os.Open(filePath)
	if err != nil {
		return nil, stats, fmt.Errorf("open pcap file: %w", err)
	}
	defer f.Close()

	src, err := newSource(f)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Nothing was cut mid-record: there is no complete header to read.
			if fi, serr := f.Stat(); serr == nil {
				err = fmt.Errorf("file is only %d bytes, too short to hold a capture file header: %w", fi.Size(), err)
			}
		}
		return nil, stats, err
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
			return packets, stats, &TruncatedError{Packets: len(packets), Err: err}
		}
		if err != nil {
			return nil, stats, fmt.Errorf("read packet: %w", err)
		}
		stats.Frames++

		lt := src.linkType(ci)
		pkt := gopacket.NewPacket(data, lt, gopacket.NoCopy)
		info, ok := packetInfo(pkt)
		if !ok {
			if linkTypeSupported(lt) {
				stats.SkippedNonIP++
			} else {
				stats.SkippedUnsupportedLink++
				if stats.UnsupportedLinkTypes == nil {
					stats.UnsupportedLinkTypes = make(map[int]int)
				}
				stats.UnsupportedLinkTypes[src.realLinkType(lt)]++
			}
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
	return packets, stats, nil
}

// linkTypeSupported reports whether gopacket has a real decoder for lt.
// gopacket stores link types in a byte, so pcap link types above 255 reach
// us with only their low eight bits (Ethernet mPackets, 274, shows up as 18).
// Link types it does not know are registered with a decoder that only
// returns an error and the name "UnknownLinkType".
func linkTypeSupported(lt layers.LinkType) bool {
	return int(lt) >= 0 && int(lt) < len(layers.LinkTypeMetadata) && layers.LinkTypeMetadata[lt].Name != "UnknownLinkType"
}

// packetInfo extracts addressing and protocol details from a decoded packet.
// It reports false if the packet has no IPv4 or IPv6 layer.
//
// The addresses are those of the IP layer that directly encloses the
// transport layer, so a tunnelled packet (GRE, IP-in-IP, IPv6-in-IPv4) is
// described by the inner packet and its ports; the outer addresses are kept
// in Tunnel.
func packetInfo(pkt gopacket.Packet) (models.PacketInfo, bool) {
	var info models.PacketInfo

	if l := pkt.Layer(layers.LayerTypeARP); l != nil {
		fillARP(&info, l.(*layers.ARP))
		return info, true
	}

	ip, transport, outer := enclosingIP(pkt)
	var ipProto uint8
	switch ip := ip.(type) {
	case *layers.IPv4:
		info.SrcIP, info.DstIP = ip.SrcIP.String(), ip.DstIP.String()
		ipProto = uint8(ip.Protocol)
	case *layers.IPv6:
		info.SrcIP, info.DstIP = ip.SrcIP.String(), ip.DstIP.String()
		ipProto = uint8(ip.NextHeader)
	default:
		return info, false
	}
	info.Tunnel = tunnelOf(outer)

	switch t := transport.(type) {
	case *layers.TCP:
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
	case *layers.UDP:
		info.Protocol = models.ProtocolUDP
		info.SrcPort, info.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		info.PayloadSize = len(t.Payload)
		info.PayloadPreview = previewPayload(t.Payload)
	case *layers.ICMPv4:
		info.Protocol = models.ProtocolICMP
		info.ICMPType, info.ICMPCode = t.TypeCode.Type(), t.TypeCode.Code()
		info.ICMPMessage = icmpMessage(info.ICMPType, info.ICMPCode)
		fillICMPOriginal(&info, t.Payload)
	case *layers.ICMPv6:
		info.Protocol = models.ProtocolICMP
	default:
		// An IP protocol the tool does not analyze: keep its name, if it is a
		// well-known one, so it is not lumped into "Other".
		info.Protocol = models.IPProtocolName(ipProto)
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

// fillICMPOriginal extracts the quoted original datagram from the payload of
// an ICMP error message (destination unreachable, source quench, redirect,
// time exceeded, parameter problem): its IPv4 header and the first bytes of
// its TCP or UDP header.
func fillICMPOriginal(info *models.PacketInfo, payload []byte) {
	switch info.ICMPType {
	case 3, 4, 5, 11, 12:
	default:
		return
	}
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return
	}
	info.ICMPOrigSrcIP = net.IP(payload[12:16]).String()
	info.ICMPOrigDstIP = net.IP(payload[16:20]).String()
	switch payload[9] {
	case 1:
		info.ICMPOrigProto = string(models.ProtocolICMP)
	case 6, 17:
		info.ICMPOrigProto = string(models.ProtocolTCP)
		if payload[9] == 17 {
			info.ICMPOrigProto = string(models.ProtocolUDP)
		}
		if len(payload) >= ihl+4 {
			info.ICMPOrigSrcPort = uint16(payload[ihl])<<8 | uint16(payload[ihl+1])
			info.ICMPOrigDstPort = uint16(payload[ihl+2])<<8 | uint16(payload[ihl+3])
		}
	default:
		info.ICMPOrigProto = fmt.Sprintf("IP proto %d", payload[9])
	}
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
	// realLinkType returns the link type number as written in the file for
	// lt, which gopacket has cut down to 8 bits, or int(lt) if unknown.
	realLinkType(lt layers.LinkType) int
	// cutShort reports, after an io.EOF, whether the file actually ended in
	// the middle of a record.
	cutShort() bool
}

type pcapSource struct {
	*pcapgo.Reader
	linkNumber int // the link type from the file header, in full
}

// cutShort is always false: pcapgo reports a record cut short as
// io.ErrUnexpectedEOF, which ReadPackets handles directly.
func (s pcapSource) cutShort() bool { return false }

func (s pcapSource) linkType(gopacket.CaptureInfo) layers.LinkType { return s.LinkType() }

func (s pcapSource) realLinkType(lt layers.LinkType) int {
	if uint8(s.linkNumber) == uint8(lt) {
		return s.linkNumber
	}
	return int(lt)
}

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

func (s ngSource) realLinkType(lt layers.LinkType) int {
	if n, ok := s.track.realLinkType(uint8(lt)); ok {
		return n
	}
	return int(lt)
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
	// The pcap header holds the link type as a 32-bit number (its top bits are
	// flags); gopacket keeps only 8 bits of it.
	hdr, _ := br.Peek(24)
	pr, err := pcapgo.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("read pcap header: %w", err)
	}
	return pcapSource{pr, pcapLinkNumber(hdr)}, nil
}

// tcpPayloadLen returns the TCP payload length the sender put on the wire,
// derived from the IP length so that captures truncated by a small snaplen
// still report the real segment size (sequence-number accounting depends on
// it). It falls back to the captured length when the IP length is unusable,
// for example with segmentation offload where it is recorded as 0.
func tcpPayloadLen(pkt gopacket.Packet, t *layers.TCP) int {
	captured := len(t.Payload)
	hdr := int(t.DataOffset) * 4

	// The length that counts is the one in the IP header around the segment,
	// which for a tunnelled packet is the inner header, not the outer one.
	var ipPayload int
	switch ip := ipAround(pkt, t).(type) {
	case *layers.IPv4:
		if ip.Length == 0 {
			return captured
		}
		ipPayload = int(ip.Length) - int(ip.IHL)*4
	case *layers.IPv6:
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

// pcapLinkNumber reads the link type from a classic pcap file header, or
// returns -1 if hdr is too short or has no known magic number.
func pcapLinkNumber(hdr []byte) int {
	if len(hdr) < 24 {
		return -1
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(hdr[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d: // written big-endian (microsecond / nanosecond)
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return -1
	}
	return int(order.Uint32(hdr[20:24]) & 0x0fffffff)
}

func isIP(l gopacket.Layer) bool {
	switch l.(type) {
	case *layers.IPv4, *layers.IPv6:
		return true
	}
	return false
}

// enclosingIP returns the IP layer that directly encloses the first
// transport layer (TCP, UDP or ICMP) of pkt, that transport layer, and the
// outermost IP layer if pkt is tunnelled (that is, if there are several IP
// layers before the transport layer); otherwise outer is nil. If there is no
// transport layer, the innermost IP layer is returned with a nil transport.
func enclosingIP(pkt gopacket.Packet) (ip, transport, outer gopacket.Layer) {
	var ips []gopacket.Layer
walk:
	for _, l := range pkt.Layers() {
		switch l.(type) {
		case *layers.IPv4, *layers.IPv6:
			ips = append(ips, l)
		case *layers.TCP, *layers.UDP, *layers.ICMPv4, *layers.ICMPv6:
			transport = l
			break walk
		}
	}
	if len(ips) == 0 {
		return nil, nil, nil
	}
	if len(ips) > 1 {
		outer = ips[0]
	}
	return ips[len(ips)-1], transport, outer
}

// ipAround returns the IP layer directly before layer l in pkt, or nil.
func ipAround(pkt gopacket.Packet, l gopacket.Layer) gopacket.Layer {
	var ip gopacket.Layer
	for _, x := range pkt.Layers() {
		if x == l {
			return ip
		}
		if isIP(x) {
			ip = x
		}
	}
	return nil
}

// tunnelOf describes the outer IP header of a tunnelled packet as
// "src>dst/KIND", or returns "" if outer is nil. KIND names the tunnel by the
// outer header's protocol: GRE, IP-in-IP, 6in4 (IPv6 in IPv4) or IPv6-in-IPv6.
func tunnelOf(outer gopacket.Layer) string {
	var src, dst net.IP
	var proto uint8
	var v4 bool
	switch ip := outer.(type) {
	case *layers.IPv4:
		src, dst, proto, v4 = ip.SrcIP, ip.DstIP, uint8(ip.Protocol), true
	case *layers.IPv6:
		src, dst, proto = ip.SrcIP, ip.DstIP, uint8(ip.NextHeader)
	default:
		return ""
	}
	kind := "tunnel"
	switch layers.IPProtocol(proto) {
	case layers.IPProtocolGRE:
		kind = "GRE"
	case layers.IPProtocolIPv4:
		kind = "IP-in-IP"
	case layers.IPProtocolIPv6:
		kind = "IPv6-in-IPv6"
		if v4 {
			kind = "6in4"
		}
	}
	return src.String() + ">" + dst.String() + "/" + kind
}
