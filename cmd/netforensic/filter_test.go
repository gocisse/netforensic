package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func intp(v int) *int { return &v }

func TestNewPacketFilterValidation(t *testing.T) {
	tests := []struct {
		name         string
		src, dst     string
		sport, dport *int
		wantErr      string
	}{
		{"all unset", "", "", nil, nil, ""},
		{"valid everything", "10.0.0.1", "::1", intp(80), intp(0), ""},
		{"bad src ip", "10.0.0", "", nil, nil, "--src-ip"},
		{"bad dst ip", "", "host.example.com", nil, nil, "--dst-ip"},
		{"negative src port", "", "", intp(-1), nil, "--src-port"},
		{"huge dst port", "", "", nil, intp(65536), "--dst-port"},
		{"max port ok", "", "", intp(65535), nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPacketFilter(tt.src, tt.dst, tt.sport, tt.dport)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestPacketFilterApply(t *testing.T) {
	pkt := func(src string, sp uint16, dst string, dp uint16) models.PacketInfo {
		return models.PacketInfo{SrcIP: src, SrcPort: sp, DstIP: dst, DstPort: dp}
	}
	packets := []models.PacketInfo{
		pkt("10.0.0.1", 1000, "10.0.0.2", 80),  // 0
		pkt("10.0.0.2", 80, "10.0.0.1", 1000),  // 1 reply
		pkt("10.0.0.1", 1001, "10.0.0.3", 443), // 2
		pkt("10.0.0.9", 1000, "10.0.0.2", 80),  // 3
		pkt("fe80::1", 5, "fe80::2", 6),        // 4 ipv6
		pkt("10.0.0.1", 0, "10.0.0.2", 0),      // 5 portless (e.g. ICMP)
	}
	tests := []struct {
		name         string
		src, dst     string
		sport, dport *int
		want         []int
	}{
		{"no filters returns everything", "", "", nil, nil, []int{0, 1, 2, 3, 4, 5}},
		{"src ip", "10.0.0.1", "", nil, nil, []int{0, 2, 5}},
		{"dst ip", "", "10.0.0.2", nil, nil, []int{0, 3, 5}},
		{"src port", "", "", intp(1000), nil, []int{0, 3}},
		{"dst port", "", "", nil, intp(80), []int{0, 3}},
		{"src ip and dst ip", "10.0.0.1", "10.0.0.2", nil, nil, []int{0, 5}},
		{"all four", "10.0.0.1", "10.0.0.2", intp(1000), intp(80), []int{0}},
		{"port zero matches portless packets", "", "", intp(0), nil, []int{5}},
		{"ipv6 matches textual variants", "FE80:0:0:0:0:0:0:1", "", nil, nil, []int{4}},
		{"contradictory filters match nothing", "10.0.0.1", "", intp(80), nil, []int{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := newPacketFilter(tt.src, tt.dst, tt.sport, tt.dport)
			require.NoError(t, err)
			got := f.apply(packets)
			want := make([]models.PacketInfo, 0)
			for _, i := range tt.want {
				want = append(want, packets[i])
			}
			assert.ElementsMatch(t, want, got)
			if len(got) == len(want) { // order is preserved
				assert.Equal(t, want, got)
			}
		})
	}
}
