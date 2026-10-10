package analyzer

import (
	"fmt"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// TruncatedCaptureIssue returns the warning for a capture file that ended
// unexpectedly after the given packets. It is anchored at the last packet's
// timestamp, the point where the data stops.
func TruncatedCaptureIssue(packets []models.PacketInfo) models.Issue {
	var last time.Time
	for _, p := range packets {
		if p.Timestamp.After(last) {
			last = p.Timestamp
		}
	}
	return models.Issue{
		ID:       "capture-truncated",
		Severity: models.SeverityWarning,
		Category: "Capture",
		Title:    "Truncated Capture",
		Description: fmt.Sprintf("The capture file ended unexpectedly. Analyzed %d packets before truncation.",
			len(packets)),
		Timestamp: last,
	}
}
