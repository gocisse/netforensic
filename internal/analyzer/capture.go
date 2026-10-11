package analyzer

import (
	"fmt"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// titleSkippedFrames is the title of the skipped-frames warning.
const titleSkippedFrames = "Skipped Frames"

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

// SkippedFramesIssue returns the note for a capture in which frames were
// read but not analyzed, because their link-layer type is not supported or
// they carry no IP or ARP traffic. Layer-2 background traffic is normal, so
// it is informational: it appears in the timeline but costs no health points
// and is never the root cause (see isNote). detail optionally says which; analyzed
// is the number of packets the analysis is based on. It is anchored at the
// first analyzed packet, the start of the capture.
func SkippedFramesIssue(skipped int, detail string, packets []models.PacketInfo) models.Issue {
	var first time.Time
	for i, p := range packets {
		if i == 0 || p.Timestamp.Before(first) {
			first = p.Timestamp
		}
	}
	verb := "were"
	if skipped == 1 {
		verb = "was"
	}
	desc := fmt.Sprintf("%s %s skipped due to unsupported link-layer types or non-IP traffic. Analysis is based on the remaining %s.",
		count(skipped, "frame", "frames"), verb, count(len(packets), "packet", "packets"))
	if detail != "" {
		desc += " (" + detail + ")"
	}
	return models.Issue{
		ID:          "capture-skipped-frames",
		Severity:    models.SeverityInfo,
		Category:    "Capture",
		Title:       titleSkippedFrames,
		Description: desc,
		Timestamp:   first,
		Count:       skipped,
	}
}
