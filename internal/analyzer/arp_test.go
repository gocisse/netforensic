package analyzer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

func arpPkt(sec float64, op, senderIP, senderMAC string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), Protocol: models.ProtocolARP, SrcIP: senderIP, DstIP: "10.0.0.99",
		ARPOperation: op, ARPSenderIP: senderIP, ARPSenderMAC: senderMAC, ARPTargetIP: "10.0.0.99"}
}

// requests returns n ARP requests spread evenly over [from, from+span] seconds.
func requests(n int, from, span float64) []models.PacketInfo {
	var out []models.PacketInfo
	for i := 0; i < n; i++ {
		out = append(out, arpPkt(from+span*float64(i)/float64(n-1), "request", "10.0.0.5", "aa:aa:aa:aa:aa:05"))
	}
	return out
}

func TestAnalyzeARPStorm(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    int
	}{
		{"no packets", nil, 0},
		{"50 requests in 10s is not a storm", requests(50, 0, 10), 0},
		{"51 requests in 10s is a storm", requests(51, 0, 10), 1},
		{"51 requests in 20s is not a storm", requests(51, 0, 20), 0},
		{"replies do not count", func() []models.PacketInfo {
			var p []models.PacketInfo
			for i := 0; i < 80; i++ {
				p = append(p, arpPkt(float64(i)/10, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"))
			}
			return p
		}(), 0},
		{"continuous flood is reported once per 51 requests", requests(120, 0, 9), 2},
		{"two separate bursts", append(requests(60, 0, 5), requests(60, 100, 5)...), 2},
		{"non-arp packets ignored", []models.PacketInfo{{Timestamp: at(0), Protocol: models.ProtocolTCP}}, 0},
		{"unsorted input is handled", func() []models.PacketInfo {
			p := requests(51, 0, 10)
			p[0], p[50] = p[50], p[0]
			return p
		}(), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storms []models.Issue
			for _, is := range analyzeARP(tt.packets) {
				if is.Title == "ARP Storm" {
					storms = append(storms, is)
					assert.Equal(t, models.SeverityWarning, is.Severity)
					assert.Equal(t, "ARP", is.Category)
				}
			}
			assert.Len(t, storms, tt.want)
		})
	}
}

func TestARPStormNamesBusiestSender(t *testing.T) {
	var packets []models.PacketInfo
	for i := 0; i < 40; i++ {
		packets = append(packets, arpPkt(float64(i)/10, "request", "10.0.0.7", "aa:aa:aa:aa:aa:07"))
	}
	for i := 0; i < 20; i++ {
		packets = append(packets, arpPkt(4+float64(i)/10, "request", "10.0.0.8", "aa:aa:aa:aa:aa:08"))
	}
	issues := analyzeARP(packets)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "10.0.0.7 (40 requests)")
}

func TestAnalyzeARPDuplicateIP(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    int
	}{
		{"one mac per ip", []models.PacketInfo{
			arpPkt(0, "request", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"),
			arpPkt(2, "request", "10.0.0.6", "aa:aa:aa:aa:aa:06")}, 0},
		{"two macs claim one ip", []models.PacketInfo{
			arpPkt(0, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05")}, 1},
		{"mac comparison ignores case", []models.PacketInfo{
			arpPkt(0, "reply", "10.0.0.5", "AA:AA:AA:AA:AA:05"), arpPkt(1, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05")}, 0},
		{"conflict reported once", []models.PacketInfo{
			arpPkt(0, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05"),
			arpPkt(2, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05")}, 1},
		{"third mac is a second conflict", []models.PacketInfo{
			arpPkt(0, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05"),
			arpPkt(2, "reply", "10.0.0.5", "cc:cc:cc:cc:cc:05")}, 2},
		{"probes from 0.0.0.0 are not claims", []models.PacketInfo{
			arpPkt(0, "request", "0.0.0.0", "aa:aa:aa:aa:aa:05"), arpPkt(1, "request", "0.0.0.0", "bb:bb:bb:bb:bb:05")}, 0},
		{"missing sender data ignored", []models.PacketInfo{
			arpPkt(0, "reply", "", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", ""), arpPkt(2, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05")}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dups []models.Issue
			for _, is := range analyzeARP(tt.packets) {
				if is.Title == "Duplicate IP Address" {
					dups = append(dups, is)
					assert.Equal(t, models.SeverityCritical, is.Severity)
					assert.Equal(t, "ARP", is.Category)
					assert.NotEmpty(t, is.ID)
				}
			}
			assert.Len(t, dups, tt.want)
		})
	}
}

func TestARPDuplicateDescriptionNamesBothMACs(t *testing.T) {
	issues := analyzeARP([]models.PacketInfo{
		arpPkt(0, "reply", "10.0.0.5", "aa:aa:aa:aa:aa:05"), arpPkt(1, "reply", "10.0.0.5", "bb:bb:bb:bb:bb:05")})
	require.Len(t, issues, 1)
	assert.Equal(t, fmt.Sprintf("IP %s is claimed by both %s and %s", "10.0.0.5", "aa:aa:aa:aa:aa:05", "bb:bb:bb:bb:bb:05"), issues[0].Description)
}
