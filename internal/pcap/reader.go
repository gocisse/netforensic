// Package pcap implements the pcap reading layer.
package pcap

import (
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

// ReadPackets opens the pcap file at filePath and returns a simplified view
// of every packet it contains. Packets without an IP layer are skipped.
func ReadPackets(filePath string) ([]models.PacketInfo, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read pcap header: %w", err)
	}

	var packets []models.PacketInfo
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}

		pkt := gopacket.NewPacket(data, r.LinkType(), gopacket.NoCopy)
		info, ok := packetInfo(pkt)
		if !ok {
			continue
		}
		info.Timestamp = ci.Timestamp
		info.Size = ci.Length
		packets = append(packets, info)
	}
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
		info.PayloadSize = len(t.Payload)
		info.TCPSeq = t.Seq
		info.TCPFlags = tcpFlags(t)
		info.TCPAck = t.Ack
		fillHTTP(&info, t.Payload)
		fillTLS(&info, t.Payload)
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		u := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		info.Protocol = models.ProtocolUDP
		info.SrcPort, info.DstPort = uint16(u.SrcPort), uint16(u.DstPort)
		info.PayloadSize = len(u.Payload)
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
