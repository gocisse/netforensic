package analyzer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gocisse/netforensic/internal/models"
)

var httpT0 = time.Unix(1700000000, 0)

func at(sec float64) time.Time { return httpT0.Add(time.Duration(sec * float64(time.Second))) }

func httpReq(sec float64, srcPort uint16, method, uri string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: "10.0.0.1", SrcPort: srcPort, DstIP: "10.0.0.2", DstPort: 80,
		Protocol: models.ProtocolTCP, HTTPMethod: method, HTTPURI: uri}
}

func httpResp(sec float64, dstPort uint16, status int) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: "10.0.0.2", SrcPort: 80, DstIP: "10.0.0.1", DstPort: dstPort,
		Protocol: models.ProtocolTCP, HTTPStatusCode: status}
}

func TestAnalyzeHTTP(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    []string
		wantSev []models.Severity
	}{
		{"no packets", nil, nil, nil},
		{"ok fast", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(0.1, 1000, 200)}, nil, nil},
		{"redirect is fine", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(0.1, 1000, 301)}, nil, nil},
		{"404", []models.PacketInfo{httpReq(0, 1000, "GET", "/x"), httpResp(0.1, 1000, 404)},
			[]string{"HTTP Client Error"}, []models.Severity{models.SeverityWarning}},
		{"400 boundary", []models.PacketInfo{httpResp(0.1, 1000, 400)},
			[]string{"HTTP Client Error"}, []models.Severity{models.SeverityWarning}},
		{"499 boundary", []models.PacketInfo{httpResp(0.1, 1000, 499)},
			[]string{"HTTP Client Error"}, []models.Severity{models.SeverityWarning}},
		{"500", []models.PacketInfo{httpReq(0, 1000, "POST", "/api"), httpResp(0.1, 1000, 500)},
			[]string{"HTTP Server Error"}, []models.Severity{models.SeverityError}},
		{"503 unsolicited", []models.PacketInfo{httpResp(0.1, 1000, 503)},
			[]string{"HTTP Server Error"}, []models.Severity{models.SeverityError}},
		{"slow 200", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(2, 1000, 200)},
			[]string{"HTTP Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"exactly 1s is not slow", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(1, 1000, 200)}, nil, nil},
		{"slow 500 reports both", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(3, 1000, 500)},
			[]string{"HTTP Server Error", "HTTP Slow Response"}, []models.Severity{models.SeverityError, models.SeverityInfo}},
		{"different connection does not match", []models.PacketInfo{httpReq(0, 1000, "GET", "/"), httpResp(5, 2000, 200)}, nil, nil},
		{"pipelined requests match in order", []models.PacketInfo{
			httpReq(0, 1000, "GET", "/a"), httpReq(0.1, 1000, "GET", "/b"),
			httpResp(0.2, 1000, 200), httpResp(3, 1000, 200)},
			[]string{"HTTP Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"out-of-order input is sorted", []models.PacketInfo{httpResp(2, 1000, 200), httpReq(0, 1000, "GET", "/")},
			[]string{"HTTP Slow Response"}, []models.Severity{models.SeverityInfo}},
		{"non-http ignored", []models.PacketInfo{{Timestamp: at(0), Protocol: models.ProtocolTCP}}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeHTTP(tt.packets)
			var titles []string
			var sevs []models.Severity
			for _, is := range issues {
				titles = append(titles, is.Title)
				sevs = append(sevs, is.Severity)
				assert.Equal(t, "HTTP", is.Category)
				assert.NotEmpty(t, is.ID)
				assert.NotEmpty(t, is.Description)
			}
			assert.Equal(t, tt.want, titles)
			assert.Equal(t, tt.wantSev, sevs)
		})
	}
}

func TestAnalyzeHTTPDescriptionNamesRequest(t *testing.T) {
	issues := analyzeHTTP([]models.PacketInfo{httpReq(0, 1000, "POST", "/api/v1"), httpResp(0.1, 1000, 500)})
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "POST /api/v1")
}

func TestAnalyzeIncludesHTTPAndTLSIssues(t *testing.T) {
	packets := []models.PacketInfo{
		httpReq(0, 1000, "GET", "/"), httpResp(0.1, 1000, 500),
		{Timestamp: at(1), SrcIP: "1.1.1.1", SrcPort: 443, DstIP: "10.0.0.1", DstPort: 5000, Protocol: models.ProtocolTCP,
			TLSHandshakeType: "Alert", TLSAlertLevel: "fatal", TLSAlertDescription: "handshake_failure"},
	}
	res := Analyze(packets, "all")
	var titles []string
	for _, is := range res.Issues {
		titles = append(titles, is.Title)
	}
	assert.ElementsMatch(t, []string{"HTTP Server Error", "TLS Handshake Failure"}, titles)
}
