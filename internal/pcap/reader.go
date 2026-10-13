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
	"slices"
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

	// SkipPreview drops the first bytes of each TCP/UDP payload that are
	// otherwise kept in PacketInfo.PayloadPreview (about 180 bytes per
	// packet with payload on a typical capture). Only stream reconstruction
	// needs them; an analysis does not.
	SkipPreview bool
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

	// NonIPTypes breaks the non-IP frames down by what they carry, by name
	// (for example "STP", "LLDP"); frames whose type is not in the tool's
	// table of well-known ones are counted as "Other".
	NonIPTypes map[string]int

	// TCPFragments counts IPv4 fragments of TCP segments, which carry no TCP
	// header of their own and are not reassembled.
	TCPFragments int

	// Metadata is what a pcapng file says about its creation, or nil (for a
	// classic pcap file, or one that says nothing).
	Metadata *models.CaptureMetadata
}

// linkTypeNames names the unsupported link types that turn up in practice.
var linkTypeNames = map[int]string{
	274: "Ethernet mPacket",
}

// maxNonIPTypes is how many kinds of non-IP frames Describe lists.
const maxNonIPTypes = 3

// nonIPBreakdown lists the most common kinds of non-IP frames, most frequent
// first, as "1200 STP, 900 LLDP, 897 Other". It shows at most maxNonIPTypes
// entries: if there are more kinds, the least common ones are added to
// "Other", so the counts always add up to the number of non-IP frames.
func nonIPBreakdown(types map[string]int) string {
	other := types[otherFrameType]
	var named []string
	for name := range types {
		if name != otherFrameType {
			named = append(named, name)
		}
	}
	sort.Slice(named, func(i, j int) bool {
		if types[named[i]] != types[named[j]] {
			return types[named[i]] > types[named[j]]
		}
		return named[i] < named[j]
	})
	room := maxNonIPTypes
	if len(named)+btoi(other > 0) > maxNonIPTypes {
		room-- // keep a place for "Other", which then also takes the rest
	}
	for _, name := range named[min(room, len(named)):] {
		other += types[name]
	}
	named = named[:min(room, len(named))]

	parts := make([]string, 0, maxNonIPTypes)
	for _, name := range named {
		parts = append(parts, fmt.Sprintf("%d %s", types[name], name))
	}
	if other > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", other, otherFrameType))
	}
	return strings.Join(parts, ", ")
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Describe says which frames were skipped, for example
// "10667 frames of unsupported link type 274 (Ethernet mPacket); 3 non-IP frames: 2 STP, 1 LLDP". It is empty
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
		part := fmt.Sprintf("%d non-IP frames", s.SkippedNonIP)
		if b := nonIPBreakdown(s.NonIPTypes); b != "" {
			part += ": " + b
		}
		parts = append(parts, part)
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
	var size int64
	if fi, serr := f.Stat(); serr == nil {
		size = fi.Size()
	}
	sized := false
	for {
		data, ci, err := src.ReadPacketData()
		if errors.Is(err, io.EOF) && !src.cutShort() {
			break
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// The file was cut off mid-record, as happens with ring buffers
			// and crashed captures. Keep what was read.
			stampConnections(packets, stats)
			annotateHandshakes(packets)
			stats.Metadata = src.metadata()
			return packets, stats, &TruncatedError{Packets: len(packets), Err: err}
		}
		if err != nil {
			return nil, stats, fmt.Errorf("read packet: %w", err)
		}
		stats.Frames++

		lt := src.linkType(ci)
		pkt := gopacket.NewPacket(data, lt, gopacket.NoCopy)
		info, ok := packetInfo(pkt)
		if ok && isTCPFragment(pkt) {
			stats.TCPFragments++
		}
		if !ok {
			if linkTypeSupported(lt) {
				stats.SkippedNonIP++
				if stats.NonIPTypes == nil {
					stats.NonIPTypes = make(map[string]int)
				}
				stats.NonIPTypes[nonIPFrameType(pkt)]++
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
		if opts.SkipPreview {
			info.PayloadPreview = nil
		}
		info.Timestamp = ci.Timestamp
		info.Size = ci.Length
		packets = append(packets, info)

		// Growing a slice of a million packets by appending copies it again
		// and again (a PacketInfo is about a kilobyte), which more than
		// doubles the memory needed at the peak. Once enough of the file has
		// been read to estimate its size, reserve room for all of it.
		if !sized && stats.Frames%4096 == 0 {
			if pos, perr := f.Seek(0, io.SeekCurrent); perr == nil {
				if est := estimateFrames(stats.Frames, pos, size); est > 0 {
					sized = true
					if est > cap(packets) {
						packets = slices.Grow(packets, est-len(packets))
					}
				}
			}
		}
	}
	stampConnections(packets, stats)
	annotateHandshakes(packets)
	stats.Metadata = src.metadata()
	return packets, stats, nil
}

// presizeAfter is how many bytes of a file are read before the number of its
// frames is estimated: far more than any read buffer, so that buffering does
// not skew the estimate, and small files, which need no help, are left alone.
const presizeAfter = 32 << 20

// estimateFrames estimates how many frames a file of size bytes holds, given
// that frames of them lie before offset pos. It returns 0 if too little has
// been read to tell (see presizeAfter) or the numbers make no sense. It errs
// on the high side by 2%, so that the slice it sizes rarely has to grow.
func estimateFrames(frames int, pos, size int64) int {
	if frames <= 0 || pos < presizeAfter || size <= pos {
		return 0
	}
	return int(float64(frames) * float64(size) / float64(pos) * 1.02)
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
		fillSIP(&info, t.Payload)
	case *layers.UDP:
		info.Protocol = models.ProtocolUDP
		info.SrcPort, info.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		info.PayloadSize = len(t.Payload)
		info.PayloadPreview = previewPayload(t.Payload)
		fillSIP(&info, t.Payload)
		fillDHCP(&info, t.Payload, info.SrcPort, info.DstPort)
		fillDHCPv6(&info, t.Payload, info.SrcPort, info.DstPort)
		fillQUIC(&info, t.Payload, info.SrcPort, info.DstPort)
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

// tcpFlagNames names the flags in the flag byte of a TCP header, as tcpFlags
// does.
func tcpFlagNames(b byte) string {
	var flags []string
	for i, name := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
		if b&(1<<i) != 0 {
			flags = append(flags, name)
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
		if payload[9] == 6 && len(payload) >= ihl+20 {
			info.ICMPOrigFullTCP = true
			info.ICMPOrigTCPSeq = binary.BigEndian.Uint32(payload[ihl+4 : ihl+8])
			info.ICMPOrigTCPFlags = tcpFlagNames(payload[ihl+13])
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
	// metadata returns what the file says about its creation, or nil.
	metadata() *models.CaptureMetadata
}

type pcapSource struct {
	*pcapgo.Reader
	linkNumber int // the link type from the file header, in full
}

// cutShort is always false: pcapgo reports a record cut short as
// io.ErrUnexpectedEOF, which ReadPackets handles directly.
func (s pcapSource) cutShort() bool { return false }

func (s pcapSource) metadata() *models.CaptureMetadata { return nil }

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
	meta  *metaCollector
}

// ReadPacketData reads the next packet and notes the interface it came from.
func (s ngSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := s.NgReader.ReadPacketData()
	if err == nil {
		s.meta.observe(s, ci)
	}
	return data, ci, err
}

// metadata returns the section header's information and the interfaces seen.
func (s ngSource) metadata() *models.CaptureMetadata { return s.meta.result(s) }

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
		return ngSource{ng, track, &metaCollector{}}, nil
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

// otherFrameType names the non-IP frames whose type the tool does not know.
const otherFrameType = "Other"

// etherTypeNames names the well-known EtherTypes of non-IP traffic.
var etherTypeNames = map[layers.EthernetType]string{
	layers.EthernetTypeLinkLayerDiscovery: "LLDP",
	layers.EthernetTypeDot1Q:              "VLAN",
	layers.EthernetTypeQinQ:               "VLAN",
	layers.EthernetTypeARP:                "ARP",
	layers.EthernetTypeMPLSUnicast:        "MPLS",
	layers.EthernetTypeMPLSMulticast:      "MPLS",
	layers.EthernetTypePPPoEDiscovery:     "PPPoE",
	layers.EthernetTypePPPoESession:       "PPPoE",
	layers.EthernetTypeEAPOL:              "EAPOL",
	layers.EthernetTypeCiscoDiscovery:     "CDP",
	layers.EthernetTypeERSPAN:             "ERSPAN",
	0x8809:                                "Slow Protocols", // LACP, Ethernet synchronization (ESMC)
	0x88f7:                                "PTP",
	0x8902:                                "CFM",
	0x9000:                                "Loopback",
	0x88e5:                                "MACsec",
	0x88e1:                                "HomePlug AV",
}

// snapTypeNames names the protocols that Cisco devices send in 802.2 SNAP
// frames, by their protocol ID.
var snapTypeNames = map[layers.EthernetType]string{
	layers.EthernetTypeCiscoDiscovery: "CDP",
	0x0111:                            "UDLD",
	0x010b:                            "STP", // PVST+
	0x2003:                            "VTP",
	0x2004:                            "DTP",
}

// llcName names the protocol in an 802.2 LLC header at the start of p
// (spanning tree, or a Cisco SNAP protocol), or returns "".
func llcName(p []byte) string {
	if len(p) < 3 {
		return ""
	}
	if p[0] == 0x42 && p[1] == 0x42 {
		return "STP"
	}
	if p[0] == 0xaa && p[1] == 0xaa && len(p) >= 8 {
		return snapTypeNames[layers.EthernetType(uint16(p[6])<<8|uint16(p[7]))]
	}
	return ""
}

// nonIPFrameType names what a frame that carries no IP or ARP is: from the
// innermost EtherType it declares, or, for IEEE 802.3 frames that give a
// length instead of a type, from the LLC header (spanning tree is
// recognized that way). Anything else is "Other".
func nonIPFrameType(pkt gopacket.Packet) string {
	name := otherFrameType
	for _, l := range pkt.Layers() {
		switch l := l.(type) {
		case *layers.Ethernet:
			if n, ok := etherTypeNames[l.EthernetType]; ok {
				name = n
			}
		case *layers.Dot1Q:
			name = "VLAN"
			if n, ok := etherTypeNames[l.Type]; ok && l.Type != layers.EthernetTypeDot1Q {
				name = n
			} else if l.Type < 0x0600 { // a length: an 802.2 LLC frame inside the VLAN tag
				if n := llcName(l.LayerPayload()); n != "" {
					return n
				}
			}
		case *layers.LLC:
			if l.DSAP == 0x42 && l.SSAP == 0x42 {
				return "STP"
			}
		case *layers.SNAP:
			if n, ok := snapTypeNames[l.Type]; ok {
				return n
			}
		case *layers.STP:
			return "STP"
		}
	}
	return name
}

// maxMetaLen caps each metadata string; the text comes from the capture file
// and is shown on a terminal.
const maxMetaLen = 200

// cleanMeta makes a string from a capture file safe to print: control
// characters (terminal escape sequences included) become spaces, surrounding
// space is trimmed, and the length is capped.
func cleanMeta(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxMetaLen {
		s = string(r[:maxMetaLen]) + "…"
	}
	return s
}

// metaCollector gathers the interfaces that packets of a pcapng file come
// from, as they are read: the reader only knows an interface once it has met
// its description block, and a merged file may hold hundreds.
type metaCollector struct {
	haveFirst  bool
	first      pcapgo.NgSectionInfo // the first section header, which names the tool
	last       int
	lastSect   pcapgo.NgSectionInfo
	haveLast   bool
	seen       map[ifaceSig]struct{}
	interfaces []models.InterfaceInfo
}

// ifaceSig is what makes two interface descriptions the same.
type ifaceSig struct {
	name, desc, filter string
	linkType           int
	snapLen            uint32
	res                pcapgo.NgResolution
}

// observe notes the interface ci belongs to, looking it up only when the
// interface or the section changed since the previous packet.
func (m *metaCollector) observe(s ngSource, ci gopacket.CaptureInfo) {
	sect := s.NgReader.SectionInfo()
	if !m.haveFirst {
		m.first, m.haveFirst = sect, true
	}
	if m.haveLast && m.last == ci.InterfaceIndex && m.lastSect == sect {
		return
	}
	m.last, m.lastSect, m.haveLast = ci.InterfaceIndex, sect, true
	if iface, err := s.NgReader.Interface(ci.InterfaceIndex); err == nil {
		m.add(s, iface)
	}
}

func (m *metaCollector) add(s ngSource, iface pcapgo.NgInterface) {
	sig := ifaceSig{iface.Name, iface.Description, iface.Filter, s.realLinkType(iface.LinkType), iface.SnapLength, iface.TimestampResolution}
	if _, ok := m.seen[sig]; ok {
		return
	}
	if m.seen == nil {
		m.seen = make(map[ifaceSig]struct{})
	}
	m.seen[sig] = struct{}{}
	m.interfaces = append(m.interfaces, models.InterfaceInfo{
		Name:        cleanMeta(iface.Name),
		Description: cleanMeta(iface.Description),
		LinkType:    linkTypeName(iface.LinkType, sig.linkType),
		SnapLen:     iface.SnapLength,
		Resolution:  resolutionName(iface.TimestampResolution),
		Filter:      cleanMeta(iface.Filter),
	})
}

// result returns the collected metadata, or nil if the file records none.
// Interfaces of the current section that no packet used are included.
func (m *metaCollector) result(s ngSource) *models.CaptureMetadata {
	for i := 0; i < s.NgReader.NInterfaces(); i++ {
		if iface, err := s.NgReader.Interface(i); err == nil {
			m.add(s, iface)
		}
	}
	info := m.first
	if !m.haveFirst {
		info = s.NgReader.SectionInfo()
	}
	md := &models.CaptureMetadata{
		CaptureTool: cleanMeta(info.Application),
		OS:          cleanMeta(info.OS),
		Hardware:    cleanMeta(info.Hardware),
		Interfaces:  m.interfaces,
	}
	if md.CaptureTool == "" && md.OS == "" && md.Hardware == "" && len(md.Interfaces) == 0 {
		return nil
	}
	return md
}

// linkTypeName names a link type: gopacket's name for one it knows, else the
// number as written in the file (see linkTypeNames).
func linkTypeName(lt layers.LinkType, real int) string {
	if n, ok := linkTypeNames[real]; ok {
		return n
	}
	if linkTypeSupported(lt) {
		return layers.LinkTypeMetadata[lt].Name
	}
	return fmt.Sprintf("type %d", real)
}

// resolutionName names a pcapng timestamp resolution, such as "microsecond".
func resolutionName(r pcapgo.NgResolution) string {
	if r.Binary() {
		return fmt.Sprintf("1/2^%d s", r.Exponent())
	}
	switch r.Exponent() {
	case 0:
		return "second"
	case 3:
		return "millisecond"
	case 6:
		return "microsecond"
	case 9:
		return "nanosecond"
	}
	return fmt.Sprintf("1/10^%d s", r.Exponent())
}

// stampConnections numbers the TCP connections and conversations of the whole
// capture, before anything filters it.
func stampConnections(packets []models.PacketInfo, stats ReadStats) {
	models.AssignConnections(packets)
	if stats.streamsReliable() {
		models.AssignStreams(packets)
	}
}

// streamsReliable reports whether the TCP conversations of the capture can be
// numbered the way Wireshark numbers tcp.stream. They cannot if frames were
// skipped that Wireshark may have decoded TCP in (an unsupported link type,
// PPPoE, MPLS, ...), or if TCP segments were IP-fragmented: the numbers of
// every later stream would be off. Skipped layer-2 control traffic that never
// carries TCP (spanning tree, LLDP, ...) does not matter.
func (s ReadStats) streamsReliable() bool {
	if s.SkippedUnsupportedLink > 0 || s.TCPFragments > 0 {
		return false
	}
	for name := range s.NonIPTypes {
		if !neverCarriesTCP[name] {
			return false
		}
	}
	return true
}

// isTCPFragment reports whether pkt is an IPv4 packet that says it carries TCP
// but has no TCP header, as the fragments of a fragmented segment.
func isTCPFragment(pkt gopacket.Packet) bool {
	ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ok && ip4.Protocol == layers.IPProtocolTCP && pkt.Layer(layers.LayerTypeTCP) == nil
}

// neverCarriesTCP names the kinds of skipped non-IP frames that cannot hold a
// TCP segment.
var neverCarriesTCP = map[string]bool{
	"STP": true, "LLDP": true, "CDP": true, "UDLD": true, "VTP": true, "DTP": true, "EAPOL": true,
	"PTP": true, "CFM": true, "Slow Protocols": true, "Loopback": true,
}
