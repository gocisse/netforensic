package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestAnalyzeWithProgressReportsEachStageInOrder(t *testing.T) {
	now := time.Unix(1700000000, 0)
	packets := []models.PacketInfo{
		{Timestamp: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80, Protocol: models.ProtocolTCP, TCPFlags: "SYN", Size: 60},
		{Timestamp: now.Add(time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 40000, Protocol: models.ProtocolTCP, TCPFlags: "SYN,ACK", Size: 60},
	}
	tests := []struct {
		name     string
		packets  []models.PacketInfo
		callback bool
	}{
		{"with packets", packets, true},
		{"without packets", nil, true},
		{"without a callback", packets, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stages []string
			var cb func(string)
			if tc.callback {
				cb = func(s string) { stages = append(stages, s) }
			}
			res := AnalyzeWithProgress(tc.packets, "all", cb)
			require.NotNil(t, res)
			if tc.callback {
				assert.Equal(t, []string{StageClassifying, StageDetecting, StageReporting}, stages)
			}
			// the callback changes nothing about the result
			plain := AnalyzeWithIssues(tc.packets, "all")
			assert.Equal(t, plain.TotalPackets, res.TotalPackets)
			assert.Equal(t, plain.TotalFlows, res.TotalFlows)
			assert.Equal(t, plain.Diagnosis.HealthScore, res.Diagnosis.HealthScore)
		})
	}
}
