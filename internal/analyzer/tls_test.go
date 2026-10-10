package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gocisse/netforensic/internal/models"
)

func clientHello(sec float64, version string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: "10.0.0.1", SrcPort: 50000, DstIP: "1.1.1.1", DstPort: 443,
		Protocol: models.ProtocolTCP, TLSHandshakeType: "ClientHello", TLSVersion: version}
}

func serverHello(sec float64, version string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: "1.1.1.1", SrcPort: 443, DstIP: "10.0.0.1", DstPort: 50000,
		Protocol: models.ProtocolTCP, TLSHandshakeType: "ServerHello", TLSVersion: version}
}

func tlsAlert(sec float64, desc string) models.PacketInfo {
	return models.PacketInfo{Timestamp: at(sec), SrcIP: "1.1.1.1", SrcPort: 443, DstIP: "10.0.0.1", DstPort: 50000,
		Protocol: models.ProtocolTCP, TLSHandshakeType: "Alert", TLSAlertLevel: "fatal", TLSAlertDescription: desc}
}

func TestAnalyzeTLS(t *testing.T) {
	tests := []struct {
		name    string
		packets []models.PacketInfo
		want    []string
		wantSev []models.Severity
	}{
		{"no packets", nil, nil, nil},
		{"clean 1.2 handshake", []models.PacketInfo{clientHello(0, "TLS 1.2"), serverHello(0.1, "TLS 1.2")}, nil, nil},
		{"clean 1.3 handshake", []models.PacketInfo{clientHello(0, "TLS 1.3"), serverHello(0.1, "TLS 1.3")}, nil, nil},
		{"1.3 offered, 1.2 chosen is not a downgrade flag", []models.PacketInfo{clientHello(0, "TLS 1.3"), serverHello(0.1, "TLS 1.2")}, nil, nil},
		{"1.2 offered, 1.0 chosen", []models.PacketInfo{clientHello(0, "TLS 1.2"), serverHello(0.1, "TLS 1.0")},
			[]string{"TLS Protocol Downgrade"}, []models.Severity{models.SeverityWarning}},
		{"1.3 offered, 1.1 chosen", []models.PacketInfo{clientHello(0, "TLS 1.3"), serverHello(0.1, "TLS 1.1")},
			[]string{"TLS Protocol Downgrade"}, []models.Severity{models.SeverityWarning}},
		{"client only offers 1.0", []models.PacketInfo{clientHello(0, "TLS 1.0"), serverHello(0.1, "TLS 1.0")}, nil, nil},
		{"server hello without client hello", []models.PacketInfo{serverHello(0.1, "TLS 1.0")}, nil, nil},
		{"unranked version ignored", []models.PacketInfo{clientHello(0, "0x7f1c"), serverHello(0.1, "TLS 1.0")}, nil, nil},
		{"server hello matches only once", []models.PacketInfo{
			clientHello(0, "TLS 1.2"), serverHello(0.1, "TLS 1.0"), serverHello(0.2, "TLS 1.0")},
			[]string{"TLS Protocol Downgrade"}, []models.Severity{models.SeverityWarning}},
		{"handshake_failure", []models.PacketInfo{tlsAlert(0, "handshake_failure")},
			[]string{"TLS Handshake Failure"}, []models.Severity{models.SeverityError}},
		{"bad_certificate", []models.PacketInfo{tlsAlert(0, "bad_certificate")},
			[]string{"TLS Handshake Failure"}, []models.Severity{models.SeverityError}},
		{"benign alert", []models.PacketInfo{tlsAlert(0, "close_notify")}, nil, nil},
		{"out-of-order input is sorted", []models.PacketInfo{serverHello(0.1, "TLS 1.0"), clientHello(0, "TLS 1.2")},
			[]string{"TLS Protocol Downgrade"}, []models.Severity{models.SeverityWarning}},
		{"non-tls ignored", []models.PacketInfo{{Timestamp: at(0), Protocol: models.ProtocolTCP}}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeTLS(tt.packets)
			var titles []string
			var sevs []models.Severity
			for _, is := range issues {
				titles = append(titles, is.Title)
				sevs = append(sevs, is.Severity)
				assert.Equal(t, "TLS", is.Category)
				assert.NotEmpty(t, is.ID)
				assert.NotEmpty(t, is.Description)
			}
			assert.Equal(t, tt.want, titles)
			assert.Equal(t, tt.wantSev, sevs)
		})
	}
}
