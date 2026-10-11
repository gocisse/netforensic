package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

func TestAnnotateFlowStatus(t *testing.T) {
	const a, b, c, d = "10.0.0.1:1-10.0.0.2:80", "10.0.0.3:1-10.0.0.2:80", "10.0.0.4:1-10.0.0.2:80", "10.0.0.5:1-10.0.0.2:80"
	flows := []models.Flow{
		{ID: a}, {ID: b}, {ID: c}, {ID: d},
		{ID: "10.0.0.6:1-10.0.0.2:80", Retransmits: 1},
		{ID: "10.0.0.7:1-10.0.0.2:80", SetupTimeMs: slowSetupMs + 1},
		{ID: "10.0.0.8:1-10.0.0.2:80", TTFBMs: slowTTFBMs + 1},
		{ID: "10.0.0.9:1-10.0.0.2:80", AvgRTTMs: slowRTTMs + 1},
		{ID: "10.0.0.10:1-10.0.0.2:80", SetupTimeMs: slowSetupMs, TTFBMs: slowTTFBMs, AvgRTTMs: slowRTTMs}, // exactly at the thresholds: fine
	}
	issues := []models.Issue{
		{ID: "1", Severity: models.SeverityError, Category: "Connection", FlowID: a},
		{ID: "2", Severity: models.SeverityInfo, Category: "Connection", FlowID: a}, // the worst counts
		{ID: "3", Severity: models.SeverityWarning, Category: "Performance", FlowID: b},
		{ID: "4", Severity: models.SeverityInfo, Category: "DNS", FlowID: c},
		{ID: "5", Severity: models.SeverityCritical, Category: "ARP", Occurrences: []models.Occurrence{{Subject: d}}},
		{ID: "6", Severity: models.SeverityError, Category: "Capture", FlowID: c}, // notes are not about flows
	}
	annotateFlowStatus(flows, issues)

	want := []struct {
		status string
		count  int
	}{
		{statusBroken, 2}, {statusSlow, 1}, {statusWorking, 1}, {statusBroken, 1},
		{statusSlow, 0}, {statusSlow, 0}, {statusSlow, 0}, {statusSlow, 0}, {statusWorking, 0},
	}
	for i, w := range want {
		assert.Equal(t, w.status, flows[i].Status, flows[i].ID)
		assert.Equal(t, w.count, flows[i].IssueCount, flows[i].ID)
	}
}
