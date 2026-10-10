// Package analyzer contains the pure analysis logic.
package analyzer

import (
	"time"

	"github.com/gocisse/netforensic/internal/models"
)

// AnalyzeFile analyzes the pcap file at filePath, restricted to the given
// service filter (e.g. "dns", "http", "tls" or "all").
//
// This is a temporary placeholder that returns a mock result.
func AnalyzeFile(filePath string, service string) (*models.AnalysisResult, error) {
	now := time.Now()
	return &models.AnalysisResult{
		FileName:     filePath,
		TotalPackets: 100,
		TotalFlows:   5,
		AnalysisTime: now,
		Duration:     "0.1s",
		Issues: []models.Issue{{
			ID:          "mock-1",
			Severity:    models.SeverityInfo,
			Category:    service,
			Title:       "Mock issue",
			Description: "Placeholder issue until real analysis is implemented",
			Timestamp:   now,
		}},
	}, nil
}
