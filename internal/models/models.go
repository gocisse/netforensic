// Package models defines the shared data structures used across netforensic.
package models

import "time"

// Protocol represents the network protocol detected.
type Protocol string

// Supported protocols.
const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolICMP Protocol = "ICMP"
	ProtocolDNS  Protocol = "DNS"
	ProtocolHTTP Protocol = "HTTP"
	ProtocolTLS  Protocol = "TLS"
)

// Severity represents the severity level of a detected issue.
type Severity string

// Issue severity levels, from least to most severe.
const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// PacketInfo represents a simplified, parsed view of a single network packet.
type PacketInfo struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    Protocol  `json:"protocol"`
	Size        int       `json:"size"`
	PayloadSize int       `json:"payload_size"`
	TCPSeq      uint32    `json:"tcp_seq,omitempty"`   // TCP sequence number; 0 for non-TCP
	TCPFlags    string    `json:"tcp_flags,omitempty"` // e.g. "SYN", "PSH,ACK"; empty for non-TCP
}

// Flow represents an aggregated view of a network connection (e.g., a TCP stream).
type Flow struct {
	ID          string    `json:"id"` // e.g., "src_ip:src_port-dst_ip:dst_port"
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    Protocol  `json:"protocol"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	PacketCount int       `json:"packet_count"`
	BytesSent   int       `json:"bytes_sent"`
	BytesRecv   int       `json:"bytes_recv"`
	Retransmits int       `json:"retransmits"` // Key metric for packet loss/slow connections
}

// Issue represents a detected forensic problem or anomaly.
type Issue struct {
	ID          string    `json:"id"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"` // e.g., "DNS", "TLS", "PacketLoss", "HTTP"
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	FlowID      string    `json:"flow_id,omitempty"` // Optional: link to specific flow
}

// AnalysisResult is the final output of the analyzer.
type AnalysisResult struct {
	FileName     string    `json:"file_name"`
	TotalPackets int       `json:"total_packets"`
	TotalFlows   int       `json:"total_flows"`
	AnalysisTime time.Time `json:"analysis_time"`
	Duration     string    `json:"duration"` // e.g., "1.2s"
	Issues       []Issue   `json:"issues"`
	TopTalkers   []Flow    `json:"top_talkers"` // Top 5 flows by bytes
}
