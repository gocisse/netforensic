// Package pcap implements the pcap reading layer.
package pcap

import (
	"errors"
	"fmt"
	"io"
	"os"

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
	return packets, nil
}

// packetInfo extracts addressing and protocol details from a decoded packet.
// It reports false if the packet has no IPv4 or IPv6 layer.
func packetInfo(pkt gopacket.Packet) (models.PacketInfo, bool) {
	var info models.PacketInfo

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
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		u := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		info.Protocol = models.ProtocolUDP
		info.SrcPort, info.DstPort = uint16(u.SrcPort), uint16(u.DstPort)
		info.PayloadSize = len(u.Payload)
	case pkt.Layer(layers.LayerTypeICMPv4) != nil, pkt.Layer(layers.LayerTypeICMPv6) != nil:
		info.Protocol = models.ProtocolICMP
	}
	return info, true
}
