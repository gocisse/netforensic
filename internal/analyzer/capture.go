package analyzer

import (
	"fmt"
	"sort"
	"strings"
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

// titleDecapsulated is the title of the note about tunnelled traffic.
const titleDecapsulated = "Decapsulated Tunnels"

// decapsulatedIssue returns the note for a capture whose packets came out of
// GRE, IP-in-IP or IPv6-in-IPv4 tunnels: they are analyzed by their inner
// addresses and ports. Like the skipped-frames note it is informational and
// costs no health points (see isNote), and it is anchored at the start of the
// capture. It reports false if no packet was tunnelled.
func decapsulatedIssue(packets []models.PacketInfo) (models.Issue, bool) {
	byKind := make(map[string]int)
	var first time.Time
	total := 0
	for i, p := range packets {
		if i == 0 || p.Timestamp.Before(first) {
			first = p.Timestamp
		}
		if p.Tunnel == "" {
			continue
		}
		byKind[p.Tunnel[strings.LastIndex(p.Tunnel, "/")+1:]]++
		total++
	}
	if total == 0 {
		return models.Issue{}, false
	}

	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%s: %d", k, byKind[k])
	}
	verb := "were"
	if total == 1 {
		verb = "was"
	}
	return models.Issue{
		ID:       "capture-decapsulated",
		Severity: models.SeverityInfo,
		Category: "Capture",
		Title:    titleDecapsulated,
		Description: fmt.Sprintf("%s %s decapsulated from tunnels (%s) and analyzed by their inner addresses and ports. Encrypted tunnels such as ESP cannot be decapsulated.",
			count(total, "packet", "packets"), verb, strings.Join(parts, ", ")),
		Timestamp: first,
		Count:     total,
	}, true
}
