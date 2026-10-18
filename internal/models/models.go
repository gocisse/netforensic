// Package models defines the shared data structures used across netforensic.
package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

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
	ProtocolSIP  Protocol = "SIP"

	ProtocolDHCP   Protocol = "DHCP"
	ProtocolDHCPv6 Protocol = "DHCPv6"
	ProtocolQUIC   Protocol = "QUIC"
)

// ipProtocolNames names the IP protocols that the tool does not analyze but
// can recognize by their protocol number, so that they show up under their
// own name instead of as "Other".
var ipProtocolNames = map[uint8]Protocol{
	2:   "IGMP",
	4:   "IP-in-IP",
	47:  "GRE",
	50:  "ESP",
	51:  "AH",
	88:  "EIGRP",
	89:  "OSPF",
	103: "PIM",
	112: "VRRP",
	115: "L2TP",
	132: "SCTP",
}

// IPProtocolName returns the name of the IP protocol number n if it is one of
// the well-known protocols the tool recognizes but does not analyze, or ""
// otherwise.
func IPProtocolName(n uint8) Protocol { return ipProtocolNames[n] }

// SIPInfo is what is read from one SIP message: the request or status line
// and the headers the analysis uses. A request has SIPMethod and SIPURI; a
// response has SIPStatusCode and SIPReason.
type SIPInfo struct {
	SIPVersion    string `json:"sip_version,omitempty"`     // "SIP/2.0"
	SIPMethod     string `json:"sip_method,omitempty"`      // INVITE, REGISTER, ...; requests only
	SIPURI        string `json:"sip_uri,omitempty"`         // request URI; requests only
	SIPStatusCode int    `json:"sip_status_code,omitempty"` // 100-699; responses only
	SIPReason     string `json:"sip_reason,omitempty"`      // reason phrase; responses only
	SIPCallID     string `json:"sip_call_id,omitempty"`
	SIPFrom       string `json:"sip_from,omitempty"`
	SIPTo         string `json:"sip_to,omitempty"`
	SIPContact    string `json:"sip_contact,omitempty"`
	SIPUserAgent  string `json:"sip_user_agent,omitempty"` // User-Agent, or Server in a response without one
	SIPCSeq       int    `json:"sip_cseq,omitempty"`       // the CSeq number
	SIPCSeqMethod string `json:"sip_cseq_method,omitempty"`
}

// HandshakeTimes is the TCP handshake timeline of one connection. A zero time
// means the event was not observed (for example a capture that started
// mid-connection).
type HandshakeTimes struct {
	TCPSynTime    time.Time `json:"tcp_syn_time"`     // first SYN from the client
	TCPSynAckTime time.Time `json:"tcp_syn_ack_time"` // server's SYN-ACK
	TCPAckTime    time.Time `json:"tcp_ack_time"`     // client's final handshake ACK
	FirstDataTime time.Time `json:"first_data_time"`  // first payload from the server after the handshake
}

// DHCPInfo is what is read from one DHCP (IPv4) message: the BOOTP header
// fields and the options the tool uses.
type DHCPInfo struct {
	MsgType      int    `json:"msg_type"`                // option 53: 1 Discover ... 8 Inform
	XID          uint32 `json:"xid"`                     // transaction ID
	ClientMAC    string `json:"client_mac,omitempty"`    // chaddr
	ClientIP     string `json:"client_ip,omitempty"`     // ciaddr, if not 0.0.0.0
	YourIP       string `json:"your_ip,omitempty"`       // yiaddr, if not 0.0.0.0
	NextServerIP string `json:"server_ip,omitempty"`     // siaddr, if not 0.0.0.0
	ServerID     string `json:"server_id,omitempty"`     // option 54, the server's identifier
	SubnetMask   string `json:"subnet_mask,omitempty"`   // option 1
	Router       string `json:"router,omitempty"`        // option 3, the first router
	DNS          string `json:"dns,omitempty"`           // option 6, the servers, comma-separated
	LeaseSeconds uint32 `json:"lease_seconds,omitempty"` // option 51
	Message      string `json:"message,omitempty"`       // option 56, for example the reason of a NAK
}

// TopologyNode is one address of a capture in the network topology.
type TopologyNode struct {
	IP string `json:"ip"`
	// Type is the role the address plays: "dns_server", "dhcp_server",
	// "server" (it answers on a well-known port) or "client".
	Type string `json:"type"`
	// TrafficVolume is the bytes of all the flows the address is in; Packets is their packets.
	TrafficVolume int64 `json:"traffic_volume"`
	Packets       int   `json:"packets"`
	// IssueCount is how many issues name the address; WorstSeverity is the worst of them.
	IssueCount    int      `json:"issue_count"`
	WorstSeverity Severity `json:"worst_severity,omitempty"`
	IsProblematic bool     `json:"is_problematic"`
	Protocols     []string `json:"protocols"`
}

// TopologyEdge is the traffic between two addresses, in the direction of most of its bytes.
type TopologyEdge struct {
	Source        string   `json:"source"`
	Target        string   `json:"target"`
	Packets       int      `json:"packets"`
	Bytes         int64    `json:"bytes"`
	Issues        int      `json:"issues"`
	WorstSeverity Severity `json:"worst_severity,omitempty"`
	// Protocol is the application protocol of most of the packets, else the transport.
	Protocol string `json:"protocol"`
}

// Topology is the network of a capture as a graph: its addresses and the
// traffic between them. A large capture is cut to its most telling nodes;
// TotalNodes and TotalEdges say how many there were before.
type Topology struct {
	Nodes      []TopologyNode `json:"nodes"`
	Edges      []TopologyEdge `json:"edges"`
	TotalNodes int            `json:"total_nodes"`
	TotalEdges int            `json:"total_edges"`
	Truncated  bool           `json:"truncated"`
}

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

	// Stream is the zero-based index of the TCP conversation this packet
	// belongs to, numbered in order of first appearance in the capture as
	// Wireshark's tcp.stream is; StreamKnown reports that it was set (see
	// AssignStreams). The reader sets it on the whole capture, before any
	// filtering.
	Stream      int  `json:"-"`
	StreamKnown bool `json:"-"`

	// Tunnel describes the outer IP header when the packet was decapsulated
	// from a tunnel, as "src>dst/KIND" (for example "10.0.0.1>10.0.0.2/GRE");
	// SrcIP, DstIP and the ports then belong to the inner packet. Empty for
	// packets that are not tunnelled.
	Tunnel string `json:"tunnel,omitempty"`

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

	// Handshake is the TCP handshake timeline of the connection this packet
	// belongs to, shared by all its packets and never modified once the reader
	// has set it; nil if no SYN of the connection was captured. In JSON its
	// four times are flat keys of the packet (tcp_syn_time, ...) at this
	// position, always present, zero when not observed; see MarshalJSON. The
	// tag only reserves that position.
	Handshake *HandshakeTimes `json:"handshake_inline__"`

	// ICMP fields are set on ICMPv4 packets (Protocol ICMP).
	ICMPType    uint8  `json:"icmp_type,omitempty"`
	ICMPCode    uint8  `json:"icmp_code,omitempty"`
	ICMPMessage string `json:"icmp_message,omitempty"` // human-readable, e.g. "Destination Unreachable: Port Unreachable"

	// The packet an ICMP error message is about, quoted in its payload:
	// the original source and destination, and their ports if the packet
	// was TCP or UDP. Empty for other ICMP messages.
	ICMPOrigSrcIP   string `json:"icmp_orig_src_ip,omitempty"`
	ICMPOrigDstIP   string `json:"icmp_orig_dst_ip,omitempty"`
	ICMPOrigSrcPort uint16 `json:"icmp_orig_src_port,omitempty"`
	ICMPOrigDstPort uint16 `json:"icmp_orig_dst_port,omitempty"`
	ICMPOrigProto   string `json:"icmp_orig_proto,omitempty"`
	// ICMPOrigFullTCP reports that the quoted packet was TCP and the error
	// quotes its whole TCP header, not just the ports (see AssignStreams).
	ICMPOrigFullTCP bool `json:"-"`
	// ICMPOrigTCPSeq and ICMPOrigTCPFlags are the sequence number and flags of
	// that quoted TCP header, when ICMPOrigFullTCP.
	ICMPOrigTCPSeq   uint32 `json:"-"`
	ICMPOrigTCPFlags string `json:"-"`

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

	// SIPInfo holds the SIP details of TCP and UDP packets whose payload starts
	// with a SIP request line or status line. It is a pointer so that the other
	// packets of a capture do not pay for it, and it is nil for them: check it
	// before reading a SIP field. SIPMethod != "" || SIPStatusCode != 0
	// identifies SIP packets. In JSON the fields are flat keys of the packet
	// (sip_method, ...) at this position; see MarshalJSON. The tag only
	// reserves that position.
	SIPInfo *SIPInfo `json:"sip_info_inline__,omitempty"`

	// DHCP is set on UDP packets that carry a DHCP (IPv4) message. It is a
	// pointer so that the other packets of a capture do not pay for it.
	DHCP *DHCPInfo `json:"dhcp,omitempty"`

	// DHCPv6 fields are set on UDP packets that carry a DHCPv6 message
	// (DHCPv6MsgType != 0). A relay message (types 12 and 13) wraps the
	// client or server message it relays: DHCPv6MsgType is the wrapper's
	// type, and the fields below it describe the innermost message.
	DHCPv6MsgType    int    `json:"dhcpv6_msg_type,omitempty"`    // 1-13, as on the wire
	DHCPv6InnerType  int    `json:"dhcpv6_inner_type,omitempty"`  // the innermost message's type (the same, unless relayed)
	DHCPv6XID        uint32 `json:"dhcpv6_xid,omitempty"`         // 24-bit transaction ID of the innermost message
	DHCPv6ClientID   string `json:"dhcpv6_client_id,omitempty"`   // client DUID in hex
	DHCPv6ServerID   string `json:"dhcpv6_server_id,omitempty"`   // server DUID in hex
	DHCPv6IAs        string `json:"dhcpv6_ias,omitempty"`         // identity associations asked for or given: IA_NA, IA_TA, IA_PD
	DHCPv6Elapsed    uint16 `json:"dhcpv6_elapsed,omitempty"`     // Elapsed Time option, in hundredths of a second
	DHCPv6StatusCode int    `json:"dhcpv6_status_code,omitempty"` // the first non-zero Status Code in the message, in an IA option or not
	DHCPv6StatusMsg  string `json:"dhcpv6_status_msg,omitempty"`  // its message text

	// QUIC fields are set on UDP packets whose payload starts with a QUIC
	// long header (QUICLongHeader). Short-header packets carry no version or
	// connection IDs and cannot be told from other UDP traffic without
	// connection state, so they are not recognized on their own.
	QUICLongHeader      bool     `json:"quic_long_header,omitempty"`
	QUICVersion         uint32   `json:"quic_version,omitempty"`          // 0 in a Version Negotiation packet
	QUICPacketTypes     string   `json:"quic_packet_types,omitempty"`     // the packets in the datagram, in order, comma-separated: Initial, 0-RTT, Handshake, Retry, Version Negotiation
	QUICDCID            string   `json:"quic_dcid,omitempty"`             // destination connection ID of the first packet, in hex
	QUICSCID            string   `json:"quic_scid,omitempty"`             // source connection ID of the first packet, in hex
	QUICOfferedVersions []uint32 `json:"quic_offered_versions,omitempty"` // the versions a Version Negotiation packet lists
}

// Flow represents an aggregated view of a network connection (e.g., a TCP stream).
type Flow struct {
	ID       string   `json:"id"` // e.g., "src_ip:src_port-dst_ip:dst_port"
	SrcIP    string   `json:"src_ip"`
	DstIP    string   `json:"dst_ip"`
	SrcPort  uint16   `json:"src_port"`
	DstPort  uint16   `json:"dst_port"`
	Protocol Protocol `json:"protocol"`
	// Tunnel identifies the tunnel the flow was decapsulated from, as
	// "KIND:outer~outer" (see TunnelKey), or is empty.
	Tunnel string `json:"tunnel,omitempty"`
	// TCPStream is the flow's Wireshark stream index (tcp.stream), for TCP
	// flows of captures in which the numbering can be worked out reliably.
	TCPStream *int `json:"tcp_stream,omitempty"`
	// Status says how the flow fared: "working", "slow" (a warning-level issue,
	// a retransmission or a slow handshake, first response or round trip) or
	// "broken" (an issue of error severity). IssueCount is the number of
	// issues that name the flow.
	Status     string `json:"status,omitempty"`
	IssueCount int    `json:"issue_count,omitempty"`
	// AppProtocol is the application protocol recognized in the flow (DNS,
	// HTTP or TLS), or empty.
	AppProtocol string    `json:"app_protocol,omitempty"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	PacketCount int       `json:"packet_count"`
	BytesSent   int       `json:"bytes_sent"`
	BytesRecv   int       `json:"bytes_recv"`
	Retransmits int       `json:"retransmits"` // Key metric for packet loss/slow connections

	// SIP details of a flow that carries SIP: the request methods seen (each
	// once, in order, joined by commas), the Call-ID of its first message and
	// the first User-Agent. A SIP flow can carry many calls; see the SIP
	// issues for the others.
	SIPMethod    string `json:"sip_method,omitempty"`
	SIPCallID    string `json:"sip_call_id,omitempty"`
	SIPUserAgent string `json:"sip_user_agent,omitempty"`

	// DHCP details of a flow that carries DHCP (IPv4): the message types seen
	// (each once, in order, by name, joined by commas), the first client
	// hardware address and the first server (its Server Identifier, else the
	// address that sent the first server message).
	DHCPMessageTypes string `json:"dhcp_message_types,omitempty"`
	DHCPClientMAC    string `json:"dhcp_client_mac,omitempty"`
	DHCPServerIP     string `json:"dhcp_server_ip,omitempty"`

	// DHCPv6 details of a flow that carries DHCPv6: the message types seen
	// (each once, in order, by name, joined by commas) and the first client
	// and server identifiers.
	DHCPv6MessageTypes string `json:"dhcpv6_message_types,omitempty"`
	DHCPv6ClientID     string `json:"dhcpv6_client_id,omitempty"`
	DHCPv6ServerID     string `json:"dhcpv6_server_id,omitempty"`

	// QUIC details of a flow that carries QUIC: the version of its first
	// packet that names one, and the long-header packet types seen (each once,
	// in order, comma-separated).
	QUICVersion     string `json:"quic_version,omitempty"`
	QUICPacketTypes string `json:"quic_packet_types,omitempty"`

	// Retransmits split by trigger: sent after three or more duplicate
	// ACKs, or after the connection had been silent (an RTO). The remainder
	// of Retransmits has neither trigger. DupAcks counts duplicate ACKs.
	FastRetransmits    int `json:"fast_retransmits,omitempty"`
	TimeoutRetransmits int `json:"timeout_retransmits,omitempty"`

	// RecoveryRetransmits counts the segments resent during the recovery
	// that a fast or timeout retransmission started; they are not counted in
	// FastRetransmits or TimeoutRetransmits.
	RecoveryRetransmits int `json:"recovery_retransmits,omitempty"`
	DupAcks             int `json:"dup_acks,omitempty"`

	// RetransmitEvents lists every retransmission in capture order.
	RetransmitEvents []RetransmitEvent `json:"-"`

	// Timeline lists the key events of a TCP flow that has issues, in
	// time order: how the connection started, when data first flowed, what
	// went wrong and how it ended. Empty for other flows.
	Timeline []FlowEvent `json:"timeline,omitempty"`

	// Performance metrics for TCP flows, in milliseconds. Zero means the
	// metric could not be measured from the capture.
	SetupTimeMs float64 `json:"setup_time_ms"` // SYN to final handshake ACK
	TTFBMs      float64 `json:"ttfb_ms"`       // handshake completion to first server data
	AvgRTTMs    float64 `json:"avg_rtt_ms"`
	MaxRTTMs    float64 `json:"max_rtt_ms"` // large values relative to the average indicate jitter
}

// ProtocolStat is the share of a capture that one protocol accounts for.
//
// Transport protocols (TCP, UDP, ICMP, ARP) partition the packets, so their
// percentages add up to 100. Application protocols (DNS, HTTP, TLS) are
// recognized from the content of a flow and count every packet of such a
// flow, including its handshake and ACKs; they overlap with the transport
// protocol that carries them.
type ProtocolStat struct {
	Protocol string  `json:"protocol"`
	Layer    string  `json:"layer"` // "transport" or "application"
	Packets  int     `json:"packets"`
	Flows    int     `json:"flows"`
	Percent  float64 `json:"percent"` // of all packets, to one decimal

	// TopFlows are the busiest flows (by bytes) of this protocol.
	TopFlows []Flow `json:"top_flows"`
}

// RetransmitEvent is one retransmitted TCP segment.
type RetransmitEvent struct {
	Time time.Time
	Seq  uint32
	Kind string // "fast", "timeout" or "other"
}

// FlowEvent is one entry in the timeline of a flow.
type FlowEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Event       string    `json:"event"`    // short name, e.g. "Timeout Retransmit"
	Severity    Severity  `json:"severity"` // INFO for normal events, WARNING or ERROR for problems
	Description string    `json:"description"`
	// FirstIssue marks the first problem in the flow: the moment it started to go wrong.
	FirstIssue bool `json:"first_issue,omitempty"`
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

	// Occurrences lists the individual events folded into an aggregated
	// issue (every affected flow, queried domain, connection or target), so
	// a UI can drill down from the summary. The analyzer also uses it for
	// correlation.
	Occurrences []Occurrence `json:"occurrences,omitempty"`

	// Protocols lists the protocols the issue involves (for example "UDP"
	// and "DNS"), so that a UI can filter issues by protocol.
	Protocols []string `json:"protocols,omitempty"`

	// WiresharkFilter is a display filter that shows the packets the issue is
	// about, to verify it in Wireshark: pasted into its filter bar, or given
	// to `tshark -Y`. For an aggregated issue it matches every occurrence
	// (or the most affected ones, if there are very many).
	WiresharkFilter string `json:"wireshark_filter,omitempty"`

	// Recommendation says what to look at or do about the issue.
	Recommendation string `json:"recommendation,omitempty"`
}

// Occurrence is one event behind an aggregated issue.
type Occurrence struct {
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"` // the flow ID, queried domain, target ip:port, ...
	// Protocol is the most specific protocol of the event: DNS, HTTP or TLS
	// if recognized, else the transport protocol.
	Protocol string  `json:"protocol,omitempty"`
	Value    float64 `json:"value,omitempty"` // a measurement for the event, such as an RTT
	Unit     string  `json:"unit,omitempty"`  // unit of Value, for example "ms"
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
	HealthScore     int             `json:"health_score"` // 100 is healthy; heavily troubled captures go below 0, down to -50
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

	// ProtocolStats is the traffic composition, most packets first.
	ProtocolStats []ProtocolStat `json:"protocol_stats"`

	Diagnosis RootCauseAnalysis `json:"diagnosis"`

	// Metadata describes how and where the capture was taken, as far as the
	// file says so (only pcapng files carry this). Nil if it says nothing.
	Metadata *CaptureMetadata `json:"metadata,omitempty"`

	// AnalysisID names this analysis on the server that holds it, for the
	// export and reload endpoints. It is set only by the web server.
	AnalysisID string `json:"analysis_id,omitempty"`

	// GoodTrafficFilter is a Wireshark display filter that hides the traffic
	// every issue is about (see analyzer.GoodTrafficFilter), or empty if no
	// issue has a filter.
	GoodTrafficFilter string `json:"good_traffic_filter"`

	// HealthyFlows is every flow that no issue names. Like Flows it is not
	// part of the `-o json` output; the web server sends it as healthy_flows.
	HealthyFlows []Flow `json:"-"`

	// Flows is every flow of the capture, for exports. It is not part of the
	// JSON output, which lists only the top flows.
	Flows []Flow `json:"-"`
}

// TunnelKey returns a direction-independent identity for the tunnel
// description t of a PacketInfo ("src>dst/KIND"): "KIND:a~b" with the two
// outer addresses in a fixed order, so both directions of one tunnel get the
// same key. It returns "" if t is empty or not in that form.
func TunnelKey(t string) string {
	slash := strings.LastIndex(t, "/")
	arrow := strings.Index(t, ">")
	if slash < 0 || arrow < 0 || arrow > slash {
		return ""
	}
	a, b, kind := t[:arrow], t[arrow+1:slash], t[slash+1:]
	if b < a {
		a, b = b, a
	}
	return kind + ":" + a + "~" + b
}

// CaptureMetadata is what a pcapng file records about its own creation: the
// section header (tool, operating system, hardware) and the interfaces the
// packets were captured on. Every field is optional in the format and may be
// empty.
type CaptureMetadata struct {
	CaptureTool string          `json:"capture_tool,omitempty"` // application that wrote the file, e.g. "Dumpcap (Wireshark) 3.4.9"
	OS          string          `json:"os,omitempty"`           // operating system of the capturing host
	Hardware    string          `json:"hardware,omitempty"`     // hardware of the capturing host
	Interfaces  []InterfaceInfo `json:"interfaces,omitempty"`   // the distinct interface configurations that packets came from
}

// InterfaceInfo describes a capture interface (a pcapng interface description
// block). Interfaces with identical descriptions are listed once.
type InterfaceInfo struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	LinkType    string `json:"link_type"`                      // for example "Ethernet"
	SnapLen     uint32 `json:"snap_len"`                       // largest captured packet; 0 means no limit
	Resolution  string `json:"timestamp_resolution,omitempty"` // for example "nanosecond"
	Filter      string `json:"filter,omitempty"`               // the capture filter in effect
}

// QUIC versions.
const (
	QUICVersionNegotiation uint32 = 0x00000000
	QUICVersion1           uint32 = 0x00000001
	QUICVersion2           uint32 = 0x6b3343cf
)

// QUICDraft returns the draft number of a QUIC draft version (0xff0000XX), and
// whether v is one.
func QUICDraft(v uint32) (int, bool) {
	if v&0xffffff00 == 0xff000000 {
		return int(v & 0xff), true
	}
	return 0, false
}

// QUICVersionName names a QUIC version: "QUIC v1", "QUIC v2", "draft-29" for
// 0xff00001d, "reserved" for the 0x?a?a?a?a values that endpoints send to
// provoke version negotiation, or the number in hex.
func QUICVersionName(v uint32) string {
	if d, ok := QUICDraft(v); ok {
		return fmt.Sprintf("draft-%d", d)
	}
	switch {
	case v == QUICVersionNegotiation:
		return "Version Negotiation"
	case v == QUICVersion1:
		return "QUIC v1"
	case v == QUICVersion2:
		return "QUIC v2"
	case v&0x0f0f0f0f == 0x0a0a0a0a:
		return fmt.Sprintf("reserved (0x%08x)", v)
	}
	return fmt.Sprintf("unknown (0x%08x)", v)
}

// sipInlineKey and handshakeInlineKey are the JSON keys reserved by the
// SIPInfo and Handshake tags of PacketInfo. MarshalJSON replaces each with the
// members of its group.
const (
	sipInlineKey       = "sip_info_inline__"
	handshakeInlineKey = "handshake_inline__"
)

// packetInfoPlain has the fields of PacketInfo and none of its methods, so
// that MarshalJSON and UnmarshalJSON can use the default encoding.
type packetInfoPlain PacketInfo

// MarshalJSON encodes p as before the SIP and handshake fields moved into
// groups: their keys are members of the packet, at the position of the group's
// field. The SIP members are left out when empty; the four handshake times are
// always written, as zero times when there is no handshake.
func (p PacketInfo) MarshalJSON() ([]byte, error) {
	var hs HandshakeTimes
	if p.Handshake != nil {
		hs = *p.Handshake
	}
	p.Handshake = &hs // p is a copy: the placeholder always carries a group
	b, err := json.Marshal(packetInfoPlain(p))
	if err != nil {
		return nil, err
	}
	if b, err = spliceMembers(b, handshakeInlineKey, hs); err != nil {
		return nil, err
	}
	if p.SIPInfo == nil {
		return b, nil
	}
	return spliceMembers(b, sipInlineKey, p.SIPInfo)
}

// spliceMembers replaces the member `"key":{...}` of the object b by the
// members of group, which is encoded as an object.
func spliceMembers(b []byte, key string, group any) ([]byte, error) {
	g, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", key, err)
	}
	k := []byte(`"` + key + `":`)
	i := bytes.Index(b, k)
	if i < 0 {
		return nil, fmt.Errorf("marshal packet: key %q not found", key)
	}
	end := i + len(k) + len(g)
	members := g[1 : len(g)-1]
	out := append([]byte(nil), b[:i]...)
	switch {
	case len(members) > 0:
		out = append(out, members...)
	case end < len(b) && b[end] == ',':
		end++ // no member left: drop the comma that followed it
	case out[len(out)-1] == ',':
		out = out[:len(out)-1]
	}
	return append(out, b[end:]...), nil
}

// UnmarshalJSON decodes the flat form written by MarshalJSON. Like decoding
// into a plain struct, it keeps the fields the input does not mention, and
// null leaves p unchanged. The SIP members and the handshake times are merged
// into copies of the existing groups, which other copies of the packet may
// share, so a group is never modified in place. SIPInfo stays nil unless the
// result has a non-empty SIP member; Handshake stays nil unless a time is not
// zero. A handshake time the input mentions replaces the existing one, a zero
// time included; a time it omits, or gives as null, is kept.
func (p *PacketInfo) UnmarshalJSON(b []byte) error {
	if string(bytes.TrimSpace(b)) == "null" {
		return nil
	}
	// The plain decoder would fill a group through the reserved key, and into
	// the existing one in place; take the group out of its way.
	hs := p.Handshake
	p.Handshake = nil
	if err := json.Unmarshal(b, (*packetInfoPlain)(p)); err != nil {
		p.Handshake = hs
		return err
	}
	p.Handshake = hs
	if err := p.mergeHandshake(b); err != nil {
		return err
	}
	var cur SIPInfo
	if p.SIPInfo != nil {
		cur = *p.SIPInfo
	}
	merged := cur
	if err := json.Unmarshal(b, &merged); err != nil {
		return err
	}
	switch {
	case merged == cur:
	case merged == (SIPInfo{}):
		p.SIPInfo = nil
	default:
		p.SIPInfo = &merged
	}
	return nil
}

// mergeHandshake applies the handshake times that the JSON object b mentions.
func (p *PacketInfo) mergeHandshake(b []byte) error {
	var raw struct {
		Syn    *time.Time `json:"tcp_syn_time"`
		SynAck *time.Time `json:"tcp_syn_ack_time"`
		Ack    *time.Time `json:"tcp_ack_time"`
		Data   *time.Time `json:"first_data_time"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if raw.Syn == nil && raw.SynAck == nil && raw.Ack == nil && raw.Data == nil {
		return nil
	}
	var merged HandshakeTimes
	if p.Handshake != nil {
		merged = *p.Handshake
	}
	for _, m := range []struct {
		in  *time.Time
		out *time.Time
	}{{raw.Syn, &merged.TCPSynTime}, {raw.SynAck, &merged.TCPSynAckTime}, {raw.Ack, &merged.TCPAckTime}, {raw.Data, &merged.FirstDataTime}} {
		if m.in != nil {
			*m.out = *m.in
		}
	}
	if merged.TCPSynTime.IsZero() && merged.TCPSynAckTime.IsZero() && merged.TCPAckTime.IsZero() && merged.FirstDataTime.IsZero() {
		p.Handshake = nil
		return nil
	}
	p.Handshake = &merged
	return nil
}
