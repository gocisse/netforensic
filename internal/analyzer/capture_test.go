package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestTruncatedCaptureIssue(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		wantMsg string
	}{
		{"several packets", []models.PacketInfo{{Timestamp: at(2)}, {Timestamp: at(9)}, {Timestamp: at(5)}},
			"The capture file ended unexpectedly. Analyzed 3 packets before truncation."},
		{"no packets", nil, "The capture file ended unexpectedly. Analyzed 0 packets before truncation."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := TruncatedCaptureIssue(tt.packets)
			assert.Equal(t, models.SeverityWarning, is.Severity)
			assert.Equal(t, "Capture", is.Category)
			assert.Equal(t, "Truncated Capture", is.Title)
			assert.Equal(t, tt.wantMsg, is.Description)
			assert.NotEmpty(t, is.ID)
		})
	}
	assert.Equal(t, at(9), TruncatedCaptureIssue([]models.PacketInfo{{Timestamp: at(2)}, {Timestamp: at(9)}, {Timestamp: at(5)}}).Timestamp,
		"anchored at the latest packet")
}

func TestAnalyzeWithIssues(t *testing.T) {
	packets := []models.PacketInfo{{Timestamp: at(0), Protocol: models.ProtocolTCP, TCPWindow: 1}, {Timestamp: at(3), Protocol: models.ProtocolTCP, TCPWindow: 1}}

	plain := Analyze(packets, "all")
	assert.Empty(t, plain.Issues)

	res := AnalyzeWithIssues(packets, "all", TruncatedCaptureIssue(packets))
	require.Len(t, res.Issues, 1)
	assert.Equal(t, "Truncated Capture", res.Issues[0].Title)
	assert.Equal(t, 90, res.Diagnosis.HealthScore, "the warning costs 10 points")
	assert.Equal(t, "Truncated Capture", res.Diagnosis.PrimaryCause)
	assert.GreaterOrEqual(t, len(res.Diagnosis.Recommendations), 2)
	assert.Len(t, res.Diagnosis.Timeline, 3, "capture start, the warning, capture end")
	assert.Equal(t, 2, res.TotalPackets, "extra issues do not change packet counts")
}
