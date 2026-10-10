package main

import (
	"fmt"
	"net"

	"github.com/gocisse/netforensic/internal/models"
)

// packetFilter selects packets by address and port. Unset criteria match
// everything; set criteria are combined with AND.
type packetFilter struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort *uint16
}

// newPacketFilter validates the raw flag values. Empty IP strings and nil
// ports mean "no filter".
func newPacketFilter(srcIP, dstIP string, srcPort, dstPort *int) (*packetFilter, error) {
	f := &packetFilter{}
	var err error
	if f.srcIP, err = parseFilterIP("--src-ip", srcIP); err != nil {
		return nil, err
	}
	if f.dstIP, err = parseFilterIP("--dst-ip", dstIP); err != nil {
		return nil, err
	}
	if f.srcPort, err = parseFilterPort("--src-port", srcPort); err != nil {
		return nil, err
	}
	if f.dstPort, err = parseFilterPort("--dst-port", dstPort); err != nil {
		return nil, err
	}
	return f, nil
}

func parseFilterIP(flag, v string) (net.IP, error) {
	if v == "" {
		return nil, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("invalid %s %q: not an IP address", flag, v)
	}
	return ip, nil
}

func parseFilterPort(flag string, v *int) (*uint16, error) {
	if v == nil {
		return nil, nil
	}
	if *v < 0 || *v > 65535 {
		return nil, fmt.Errorf("invalid %s %d: must be between 0 and 65535", flag, *v)
	}
	p := uint16(*v)
	return &p, nil
}

// active reports whether any criterion is set.
func (f *packetFilter) active() bool {
	return f.srcIP != nil || f.dstIP != nil || f.srcPort != nil || f.dstPort != nil
}

// matches reports whether p satisfies every set criterion.
func (f *packetFilter) matches(p models.PacketInfo) bool {
	if f.srcIP != nil && !f.srcIP.Equal(net.ParseIP(p.SrcIP)) {
		return false
	}
	if f.dstIP != nil && !f.dstIP.Equal(net.ParseIP(p.DstIP)) {
		return false
	}
	if f.srcPort != nil && *f.srcPort != p.SrcPort {
		return false
	}
	if f.dstPort != nil && *f.dstPort != p.DstPort {
		return false
	}
	return true
}

// apply returns the packets that match, in their original order.
func (f *packetFilter) apply(packets []models.PacketInfo) []models.PacketInfo {
	if !f.active() {
		return packets
	}
	out := make([]models.PacketInfo, 0, len(packets))
	for _, p := range packets {
		if f.matches(p) {
			out = append(out, p)
		}
	}
	return out
}
