package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestPrintPacketTable(t *testing.T) {
	ts := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	tests := []struct {
		name   string
		packet models.PacketInfo
		want   []string
	}{
		{"tcp", models.PacketInfo{Timestamp: ts, SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80,
			Protocol: models.ProtocolTCP, Size: 100, TCPFlags: "SYN,ACK", TCPSeq: 1000},
			[]string{"2023-11-14 22:13:20.000", "10.0.0.1:12345", "10.0.0.2:80", "TCP", "100", "SYN,ACK", "1000"}},
		{"udp has no flags or seq", models.PacketInfo{Timestamp: ts, SrcIP: "1.1.1.1", SrcPort: 5, DstIP: "8.8.8.8", DstPort: 53,
			Protocol: models.ProtocolUDP, Size: 60},
			[]string{"1.1.1.1:5", "8.8.8.8:53", "UDP", "60", "-"}},
		{"icmp without ports", models.PacketInfo{Timestamp: ts, SrcIP: "1.1.1.1", DstIP: "8.8.8.8",
			Protocol: models.ProtocolICMP, Size: 84},
			[]string{"1.1.1.1  ", "8.8.8.8  ", "ICMP"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, printPacketTable(&buf, []models.PacketInfo{tt.packet}))
			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			require.Len(t, lines, 3)
			assert.Contains(t, lines[0], "SOURCE")
			for _, w := range tt.want {
				assert.Contains(t, lines[2], w)
			}
		})
	}
}
