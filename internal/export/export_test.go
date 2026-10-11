package export

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func TestTables(t *testing.T) {
	ts := time.Date(2024, 3, 1, 12, 30, 0, 500_000_000, time.UTC)
	res := &models.AnalysisResult{
		Flows: []models.Flow{
			{ID: "a", PacketCount: 1, BytesSent: 10, Protocol: models.ProtocolUDP},
			{ID: "b", PacketCount: 5, BytesSent: 100, BytesRecv: 200, Protocol: models.ProtocolTCP, SetupTimeMs: 12.5},
		},
		Issues: []models.Issue{
			{ID: "i1", Severity: models.SeverityError, Category: "Connection", Title: "T, with comma", Description: "line one\nline \"two\"", FlowID: "b", Count: 2, Timestamp: ts},
			{ID: "i2", Severity: models.SeverityInfo, Category: "DNS", Title: "t", Description: "=SUM(A1)", Occurrences: []models.Occurrence{{Subject: "a"}}},
		},
		ProtocolStats: []models.ProtocolStat{{Protocol: "TCP", Layer: "transport", Packets: 5, Flows: 1, Percent: 83.3}},
	}
	tables := Tables(res)
	require.Len(t, tables, 3)
	for i, tb := range tables {
		assert.Equal(t, Suffixes[i], tb.Suffix)
	}

	read := func(tb Table) [][]string {
		var buf bytes.Buffer
		require.NoError(t, tb.Write(&buf))
		rows, err := csv.NewReader(&buf).ReadAll()
		require.NoError(t, err)
		return rows
	}

	flows := read(tables[0])
	assert.Equal(t, []string{"flow_id", "packets", "bytes", "setup_time_ms", "ttfb_ms", "avg_rtt_ms", "max_rtt_ms", "protocol", "issues"}, flows[0])
	assert.Equal(t, []string{"b", "5", "300", "12.50", "", "", "", "TCP", "1"}, flows[1], "the busiest first; one issue is about it")
	assert.Equal(t, []string{"a", "1", "10", "", "", "", "", "UDP", "1"}, flows[2], "an event's subject counts too")

	issues := read(tables[1])
	assert.Equal(t, "line one\nline \"two\"", issues[1][4], "newlines and quotes survive")
	assert.Equal(t, "T, with comma", issues[1][3])
	assert.Equal(t, "2024-03-01T12:30:00.5Z", issues[1][8])
	assert.Equal(t, "'=SUM(A1)", issues[2][4], "a formula is neutralized")

	assert.Equal(t, [][]string{{"protocol", "layer", "packets", "flows", "percent"}, {"TCP", "transport", "5", "1", "83.3"}}, read(tables[2]))

	empty := Tables(&models.AnalysisResult{})
	for _, tb := range empty {
		assert.Len(t, read(tb), 1, "just the header")
	}
}
