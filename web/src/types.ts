/** Types for the JSON returned by POST /api/analyze. */

export type Severity = 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO'

/** One event behind an aggregated issue (a flow, a queried domain, ...). */
export interface Occurrence {
  time: string
  subject: string
  /** Most specific protocol of the event: DNS, HTTP or TLS, else the transport. */
  protocol?: string
  value?: number
  unit?: string
}

export interface Issue {
  id: string
  severity: Severity
  category: string
  title: string
  description: string
  timestamp: string
  flow_id?: string
  domain?: string
  target?: string
  /** Protocols the issue involves, for filtering (for example UDP and DNS). */
  protocols?: string[]
  /** Number of events folded into this issue. */
  count?: number
  occurrences?: Occurrence[]
  /** A Wireshark display filter that shows the packets the issue is about. */
  wireshark_filter?: string
  /** What to do about it. */
  recommendation?: string
}

export interface TimelineEvent {
  timestamp: string
  event_type: string
  description: string
  severity: Severity
}

export interface Diagnosis {
  /** 100 is healthy; badly troubled captures go below 0, down to -50. */
  health_score: number
  primary_cause: string
  confidence: string
  summary: string
  timeline: TimelineEvent[]
  recommendations: string[]
}

/** One entry in the timeline of a TCP flow that has issues. */
export interface FlowEvent {
  /** When it happened (RFC 3339). */
  timestamp: string
  /** Short name, for example "Timeout Retransmit". INFO events are normal; WARNING and ERROR are problems. */
  event: string
  severity: Severity
  description: string
  /** Set on the first problem of the flow: the moment it started to go wrong. */
  first_issue?: boolean
}

export interface Flow {
  id: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  /** Transport protocol (TCP, UDP, ICMP, ARP) or the name of another IP protocol (OSPF, GRE, ...); empty if unknown. */
  protocol: string
  /** Wireshark's tcp.stream index of the flow, when the capture's streams can be numbered reliably. */
  tcp_stream?: number
  /** Set when the flow was decapsulated from a tunnel: "KIND:outer~outer". */
  tunnel?: string
  /** DNS, HTTP, TLS, SIP, DHCPv6 or QUIC, if recognized in the flow. */
  app_protocol?: string
  /** SIP flows: the request methods seen (comma-separated), the first Call-ID and the first User-Agent. */
  sip_method?: string
  sip_call_id?: string
  sip_user_agent?: string
  /** DHCPv6 flows: the message types seen (comma-separated) and the first client and server identifiers (hex). */
  dhcpv6_message_types?: string
  dhcpv6_client_id?: string
  dhcpv6_server_id?: string
  /** QUIC flows: the version ("QUIC v1", "draft-29", ...) and the long-header packet types seen (comma-separated). */
  quic_version?: string
  quic_packet_types?: string
  start_time: string
  end_time: string
  packet_count: number
  bytes_sent: number
  bytes_recv: number
  retransmits: number
  setup_time_ms: number
  ttfb_ms: number
  avg_rtt_ms: number
  max_rtt_ms: number
  /** How the flow fared: working, slow (warnings, retransmissions, slow timings) or broken (an error-level issue). */
  status?: 'working' | 'slow' | 'broken'
  /** The number of issues that name the flow. */
  issue_count?: number
  /** Key events of a TCP flow with issues, in time order. */
  timeline?: FlowEvent[]
}

/** The share of a capture that one protocol accounts for. */
export interface ProtocolStat {
  protocol: string
  /** Transport protocols partition the packets; application protocols overlap them. */
  layer: 'transport' | 'application'
  packets: number
  flows: number
  /** Share of all packets, in percent, to one decimal. */
  percent: number
  /** The busiest flows of this protocol. */
  top_flows: Flow[]
}

/** A full analysis. */
export interface AnalysisResult {
  file_name: string
  total_packets: number
  total_flows: number
  analysis_time: string
  duration: string
  issues: Issue[]
  top_talkers: Flow[]
  slow_flows: Flow[]
  protocol_stats: ProtocolStat[]
  diagnosis: Diagnosis
  /** Names this analysis on the server, which keeps it for a while: the page reloads it and exports from it. */
  analysis_id?: string
  /** Every flow, which the page filters and sums up itself. */
  flows?: Flow[]
  /** The flows no issue names, for the Good Traffic tab. */
  healthy_flows?: Flow[]
  /** A Wireshark display filter that hides everything the issues point at; empty if no issue has a filter. */
  good_traffic_filter?: string
}

/** The answer for a capture that holds nothing to analyze. */
export interface EmptyResult {
  file_name: string
  total_packets: 0
  total_flows: 0
  issues: Issue[]
  message: string
}

export type ApiResult = AnalysisResult | EmptyResult

export function isEmptyResult(r: ApiResult): r is EmptyResult {
  return !('diagnosis' in r) || r.diagnosis == null
}
