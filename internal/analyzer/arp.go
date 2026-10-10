package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

const (
	arpStormThreshold = 50 // more than this many requests...
	arpStormWindow    = 10 * time.Second
)

// analyzeARP reports:
//   - ARP storms: more than 50 ARP requests within 10 seconds (warning)
//   - duplicate IPs: one IP address claimed by different MAC addresses
//     (critical)
//
// ARP probes (sender IP 0.0.0.0) are not treated as address claims.
func analyzeARP(packets []models.PacketInfo) []models.Issue {
	var arp []models.PacketInfo
	for _, p := range packets {
		if p.Protocol == models.ProtocolARP {
			arp = append(arp, p)
		}
	}
	sort.SliceStable(arp, func(i, j int) bool { return arp[i].Timestamp.Before(arp[j].Timestamp) })

	return append(arpStorms(arp), arpDuplicates(arp)...)
}

// arpStorms finds bursts of ARP requests using a sliding window. After a
// storm is reported the window restarts, so a continuous flood yields one
// issue per 51 requests rather than one per packet.
func arpStorms(arp []models.PacketInfo) []models.Issue {
	var reqs []models.PacketInfo
	for _, p := range arp {
		if p.ARPOperation == "request" {
			reqs = append(reqs, p)
		}
	}

	var issues []models.Issue
	start := 0
	for end := range reqs {
		for reqs[end].Timestamp.Sub(reqs[start].Timestamp) > arpStormWindow {
			start++
		}
		n := end - start + 1
		if n <= arpStormThreshold {
			continue
		}
		bySender := make(map[string]int)
		top, topN := "", 0
		for _, r := range reqs[start : end+1] {
			bySender[r.ARPSenderIP]++
			if c := bySender[r.ARPSenderIP]; c > topN || (c == topN && r.ARPSenderIP < top) {
				top, topN = r.ARPSenderIP, c
			}
		}
		issues = append(issues, models.Issue{
			ID:       fmt.Sprintf("arp-storm-%d", reqs[start].Timestamp.UnixNano()),
			Severity: models.SeverityWarning,
			Category: "ARP",
			Title:    "ARP Storm",
			Description: fmt.Sprintf("%d ARP requests within %s starting at %s; busiest sender %s (%d requests)",
				n, reqs[end].Timestamp.Sub(reqs[start].Timestamp).Round(time.Millisecond), reqs[start].Timestamp.UTC().Format("15:04:05"), top, topN),
			Timestamp: reqs[start].Timestamp,
		})
		start = end + 1
		if start >= len(reqs) {
			break
		}
	}
	return issues
}

// arpDuplicates reports each IP address seen with more than one sender MAC.
func arpDuplicates(arp []models.PacketInfo) []models.Issue {
	firstMAC := make(map[string]string)
	reported := make(map[string]bool)
	var issues []models.Issue

	for _, p := range arp {
		ip, mac := p.ARPSenderIP, strings.ToLower(p.ARPSenderMAC)
		if ip == "" || ip == "0.0.0.0" || mac == "" {
			continue
		}
		prev, seen := firstMAC[ip]
		if !seen {
			firstMAC[ip] = mac
			continue
		}
		if prev == mac || reported[ip+"/"+mac] {
			continue
		}
		reported[ip+"/"+mac] = true
		issues = append(issues, models.Issue{
			ID:          fmt.Sprintf("arp-duplicate-%s-%s", ip, mac),
			Severity:    models.SeverityCritical,
			Category:    "ARP",
			Title:       "Duplicate IP Address",
			Description: fmt.Sprintf("IP %s is claimed by both %s and %s", ip, prev, mac),
			Timestamp:   p.Timestamp,
		})
	}
	return issues
}
