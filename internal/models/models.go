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
	ProtocolARP  Protocol = "ARP"
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
	TCPSeq      uint32    `json:"tcp_seq,omitempty"`    // TCP sequence number; 0 for non-TCP
	TCPFlags    string    `json:"tcp_flags,omitempty"`  // e.g. "SYN", "PSH,ACK"; empty for non-TCP
	TCPAck      uint32    `json:"tcp_ack,omitempty"`    // TCP acknowledgment number; 0 for non-TCP
	TCPWindow   uint32    `json:"tcp_window,omitempty"` // advertised receive window as in the header (unscaled); packet sources must set it, since 0 means a zero window

	// PayloadPreview holds the first bytes (at most 512) of the TCP or UDP
	// payload for stream display. It is not serialized.
	PayloadPreview []byte `json:"-"`
	// Payload is the complete transport payload. It is only filled when the
	// capture is read with pcap.ReadOptions.FullPayload.
	Payload []byte `json:"-"`

	// Conn is the zero-based index of the TCP connection attempt this
	// packet belongs to on its 4-tuple; ConnKnown reports that it was set
	// (see AssignConnections). The reader sets it on the whole capture so
	// that later filtering cannot merge reused ports again.
	Conn      int  `json:"-"`
	ConnKnown bool `json:"-"`

	// TCP handshake timeline of the flow this packet belongs to. The reader
	// fills these on every packet of a flow once the whole capture has been
	// read; a zero time means the event was not observed (for example a
	// capture that started mid-connection).
	TCPSynTime    time.Time `json:"tcp_syn_time,omitempty"`     // first SYN from the client
	TCPSynAckTime time.Time `json:"tcp_syn_ack_time,omitempty"` // server's SYN-ACK
	TCPAckTime    time.Time `json:"tcp_ack_time,omitempty"`     // client's final handshake ACK
	FirstDataTime time.Time `json:"first_data_time,omitempty"`  // first payload from the server after the handshake

	// ICMP fields are set on ICMPv4 packets (Protocol ICMP).
	ICMPType    uint8  `json:"icmp_type,omitempty"`
	ICMPCode    uint8  `json:"icmp_code,omitempty"`
	ICMPMessage string `json:"icmp_message,omitempty"` // human-readable, e.g. "Destination Unreachable: Port Unreachable"

	// ARP fields are set on ARP packets (Protocol ARP). SrcIP and DstIP hold
	// the sender and target protocol addresses.
	ARPOperation string `json:"arp_operation,omitempty"` // "request" or "reply"
	ARPSenderIP  string `json:"arp_sender_ip,omitempty"`
	ARPSenderMAC string `json:"arp_sender_mac,omitempty"`
	ARPTargetIP  string `json:"arp_target_ip,omitempty"`

	// DNS fields are set only on packets that carry a decoded DNS message
	// with at least one question; DNSQueryName != "" identifies such packets.
	DNSID           uint16   `json:"dns_id,omitempty"`            // transaction ID, used to match queries to responses
	DNSQueryName    string   `json:"dns_query_name,omitempty"`    // domain being queried
	DNSResponseType string   `json:"dns_response_type,omitempty"` // first answer's type, else the question type (e.g. "A")
	DNSResponseCode string   `json:"dns_response_code,omitempty"` // e.g. "NOERROR", "NXDOMAIN"; empty for queries
	DNSIsQuery      bool     `json:"dns_is_query,omitempty"`
	DNSAnswers      []string `json:"dns_answers,omitempty"` // e.g. "A 93.184.216.34", "CNAME example.org"

	// HTTP fields are set on TCP packets whose payload starts with an HTTP/1.x
	// request line (method, URI) or status line (status code).
	HTTPMethod     string `json:"http_method,omitempty"`
	HTTPURI        string `json:"http_uri,omitempty"`
	HTTPHost       string `json:"http_host,omitempty"` // Host header of a request
	HTTPStatusCode int    `json:"http_status_code,omitempty"`

	// TLS fields are set on TCP packets whose payload starts with a TLS record.
	// TLSVersion is the highest version offered by a ClientHello or the
	// version selected by a ServerHello (e.g. "TLS 1.2").
	TLSHandshakeType    string `json:"tls_handshake_type,omitempty"` // e.g. "ClientHello", "ServerHello", "Alert"
	TLSVersion          string `json:"tls_version,omitempty"`
	TLSAlertLevel       string `json:"tls_alert_level,omitempty"`       // "warning" or "fatal"
	TLSAlertDescription string `json:"tls_alert_description,omitempty"` // e.g. "handshake_failure"
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

	// Performance metrics for TCP flows, in milliseconds. Zero means the
	// metric could not be measured from the capture.
	SetupTimeMs float64 `json:"setup_time_ms"` // SYN to final handshake ACK
	TTFBMs      float64 `json:"ttfb_ms"`       // handshake completion to first server data
	AvgRTTMs    float64 `json:"avg_rtt_ms"`
	MaxRTTMs    float64 `json:"max_rtt_ms"` // large values relative to the average indicate jitter
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
	Domain      string    `json:"domain,omitempty"`  // Optional: domain or HTTP host involved, used for correlation
	Target      string    `json:"target,omitempty"`  // Optional: "ip:port" the issue is about, used for correlation
	Count       int       `json:"count,omitempty"`   // Optional: number of events folded into this issue
}

// TimelineEvent is one entry in the chronological incident timeline.
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // e.g. "root_cause", "symptom", "issue", "capture_start"
	Description string    `json:"description"`
	Severity    Severity  `json:"severity"`
}

// RootCauseAnalysis is the correlated diagnosis of a capture.
type RootCauseAnalysis struct {
	HealthScore     int             `json:"health_score"` // 0-100, 100 is healthy
	PrimaryCause    string          `json:"primary_cause"`
	Confidence      string          `json:"confidence"` // "high", "medium" or "low"
	Summary         string          `json:"summary"`
	Timeline        []TimelineEvent `json:"timeline"`
	Recommendations []string        `json:"recommendations"`
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
	SlowFlows    []Flow    `json:"slow_flows"`  // Top 5 flows by worst timing metric

	Diagnosis RootCauseAnalysis `json:"diagnosis"`
}
