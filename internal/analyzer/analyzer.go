// Package analyzer contains the analysis logic. Everything except AnalyzeFile,
// which loads the capture, is pure and operates on in-memory models.
package analyzer

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
	"github.com/gocisse/netforensic/internal/pcap"
)

const topTalkerCount = 5

// AnalyzeFile reads the pcap file at filePath, restricts it to the given
// service filter ("all", "dns", "http", "tls", "https" or a port number),
// and returns the aggregated flows, top talkers and detected issues.
func AnalyzeFile(filePath string, service string) (*models.AnalysisResult, error) {
	start := time.Now()

	port, matchAll, err := parseService(service)
	if err != nil {
		return nil, err
	}

	packets, err := pcap.ReadPackets(filePath)
	if err != nil {
		return nil, fmt.Errorf("read packets: %w", err)
	}
	if !matchAll {
		packets = filterByPort(packets, port)
	}

	flows := aggregateFlows(packets)
	issues := detectIssues(flows)

	return &models.AnalysisResult{
		FileName:     filePath,
		TotalPackets: len(packets),
		TotalFlows:   len(flows),
		AnalysisTime: start,
		Duration:     captureDuration(packets).String(),
		Issues:       issues,
		TopTalkers:   topTalkers(flows, topTalkerCount),
	}, nil
}

// parseService maps a service filter to a port. matchAll is true for "all".
func parseService(service string) (port uint16, matchAll bool, err error) {
	switch strings.ToLower(service) {
	case "all", "":
		return 0, true, nil
	case "dns":
		return 53, false, nil
	case "http":
		return 80, false, nil
	case "tls", "https":
		return 443, false, nil
	}
	n, convErr := strconv.ParseUint(service, 10, 16)
	if convErr != nil {
		return 0, false, fmt.Errorf("unknown service %q", service)
	}
	return uint16(n), false, nil
}

// filterByPort keeps packets whose source or destination port equals port.
func filterByPort(packets []models.PacketInfo, port uint16) []models.PacketInfo {
	var out []models.PacketInfo
	for _, p := range packets {
		if p.SrcPort == port || p.DstPort == port {
			out = append(out, p)
		}
	}
	return out
}

// captureDuration returns the time between the earliest and latest packet.
func captureDuration(packets []models.PacketInfo) time.Duration {
	if len(packets) == 0 {
		return 0
	}
	first, last := packets[0].Timestamp, packets[0].Timestamp
	for _, p := range packets[1:] {
		if p.Timestamp.Before(first) {
			first = p.Timestamp
		}
		if p.Timestamp.After(last) {
			last = p.Timestamp
		}
	}
	return last.Sub(first)
}

type endpoint struct {
	ip   string
	port uint16
}

func (e endpoint) less(o endpoint) bool {
	if e.ip != o.ip {
		return e.ip < o.ip
	}
	return e.port < o.port
}

func (e endpoint) String() string { return fmt.Sprintf("%s:%d", e.ip, e.port) }

type flowKey struct {
	a, b  endpoint
	proto models.Protocol
}

// aggregateFlows groups packets into bidirectional flows. Packets A->B and
// B->A share one flow whose canonical source is the lesser (IP, port)
// endpoint. BytesSent counts bytes from the canonical source and BytesRecv
// bytes from the canonical destination.
//
// Retransmits is not populated yet: PacketInfo carries no TCP sequence
// numbers to detect them from.
func aggregateFlows(packets []models.PacketInfo) []models.Flow {
	byKey := make(map[flowKey]*models.Flow)

	for _, p := range packets {
		src := endpoint{p.SrcIP, p.SrcPort}
		dst := endpoint{p.DstIP, p.DstPort}
		forward := !dst.less(src)
		a, b := src, dst
		if !forward {
			a, b = dst, src
		}

		key := flowKey{a, b, p.Protocol}
		f, ok := byKey[key]
		if !ok {
			f = &models.Flow{
				ID:        a.String() + "-" + b.String(),
				SrcIP:     a.ip,
				DstIP:     b.ip,
				SrcPort:   a.port,
				DstPort:   b.port,
				Protocol:  p.Protocol,
				StartTime: p.Timestamp,
				EndTime:   p.Timestamp,
			}
			byKey[key] = f
		}

		f.PacketCount++
		if forward {
			f.BytesSent += p.Size
		} else {
			f.BytesRecv += p.Size
		}
		if p.Timestamp.Before(f.StartTime) {
			f.StartTime = p.Timestamp
		}
		if p.Timestamp.After(f.EndTime) {
			f.EndTime = p.Timestamp
		}
	}

	flows := make([]models.Flow, 0, len(byKey))
	for _, f := range byKey {
		flows = append(flows, *f)
	}
	sort.Slice(flows, func(i, j int) bool {
		if !flows[i].StartTime.Equal(flows[j].StartTime) {
			return flows[i].StartTime.Before(flows[j].StartTime)
		}
		return flows[i].ID < flows[j].ID
	})
	return flows
}

// detectIssues inspects flows and returns any anomalies found.
func detectIssues(flows []models.Flow) []models.Issue {
	var issues []models.Issue
	for _, f := range flows {
		if f.Retransmits > 0 {
			issues = append(issues, models.Issue{
				ID:          "packetloss-" + f.ID,
				Severity:    models.SeverityWarning,
				Category:    "PacketLoss",
				Title:       "TCP Retransmissions detected",
				Description: fmt.Sprintf("flow %s had %d retransmitted packets", f.ID, f.Retransmits),
				Timestamp:   f.StartTime,
				FlowID:      f.ID,
			})
		}
	}
	return issues
}

// topTalkers returns up to n flows with the most total bytes, descending.
func topTalkers(flows []models.Flow, n int) []models.Flow {
	sorted := append([]models.Flow(nil), flows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].BytesSent+sorted[i].BytesRecv > sorted[j].BytesSent+sorted[j].BytesRecv
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}
