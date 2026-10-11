import type { Flow, Issue, Occurrence, Severity } from './types'

export interface Tone {
  label: string
  /** Tailwind classes for the score number. */
  text: string
  /** Tailwind classes for the border and the tint of the card. */
  ring: string
  bg: string
  /** The color of the accent bar. */
  bar: string
}

/**
 * Colors the health score: green from 80, yellow from 40, red below that
 * (including negative scores). The label follows the CLI's bands.
 */
export function healthTone(score: number): Tone {
  const label =
    score >= 90 ? 'Healthy' : score >= 70 ? 'Degraded' : score >= 40 ? 'Unhealthy' : score >= 0 ? 'Critical' : 'Catastrophic'
  if (score >= 80) return { label, text: 'text-success-600 dark:text-success-400', ring: 'border-success-200 dark:border-success-500/40', bg: 'bg-success-25 dark:bg-success-500/10', bar: 'bg-success-500' }
  if (score >= 40) return { label, text: 'text-warning-600 dark:text-warning-400', ring: 'border-warning-200 dark:border-warning-500/40', bg: 'bg-warning-25 dark:bg-warning-500/10', bar: 'bg-warning-500' }
  return { label, text: 'text-error-600 dark:text-error-400', ring: 'border-error-200 dark:border-error-500/40', bg: 'bg-error-25 dark:bg-error-500/10', bar: 'bg-error-500' }
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 3, ERROR: 2, WARNING: 1, INFO: 0 }

/** How severe a severity is: higher is worse. */
export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity]
}

/** The badge color of a severity. */
export function severityColor(severity: Severity): 'error' | 'warning' | 'info' {
  switch (severity) {
    case 'CRITICAL':
    case 'ERROR':
      return 'error'
    case 'WARNING':
      return 'warning'
    default:
      return 'info'
  }
}

/** Orders issues most severe first, then by how many events they cover. */
export function sortIssues(issues: Issue[]): Issue[] {
  return [...issues].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.count ?? 1) - (a.count ?? 1),
  )
}

/** Titles of issues that describe the capture file, not the traffic. */
export const NOTE_TITLES = ['Truncated Capture', 'Skipped Frames', 'Decapsulated Tunnels'] as const

/** Column heading for the subject of an issue's occurrences. */
export function subjectLabel(issue: Issue): string {
  switch (issue.category) {
    case 'DNS':
      return 'Domain'
    case 'ICMP':
      return 'Target'
    case 'Performance':
      return 'Flow'
    case 'Connection':
      return 'Connection'
    case 'PacketLoss':
      return 'Flow'
    case 'QUIC':
      return 'Flow'
    case 'DHCPv6':
      // the failure rate is per server; the rest are listed by client
      return issue.title === 'High DHCPv6 Failure Rate' ? 'Server' : 'Client'
    case 'SIP':
      // the error rate is per flow; the failures themselves are listed by Call-ID
      return issue.title === 'High SIP Error Rate' ? 'Flow' : 'Call-ID'
    default:
      return 'Subject'
  }
}

/** Formats an ISO timestamp as "2006-01-02 15:04:05.000" in UTC. */
export function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toISOString().replace('T', ' ').slice(0, 23)
}

/** Formats a measurement with its unit, for example "7638.96 ms". */
export function formatValue(o: Occurrence): string {
  if (o.value === undefined) return ''
  return o.unit ? `${o.value} ${o.unit}` : String(o.value)
}

/** The protocols offered by the protocol filter. */
export const PROTOCOL_FILTERS = ['All', 'TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'SIP', 'DHCPv6', 'QUIC', 'ARP', 'ICMP'] as const
export type ProtocolFilter = (typeof PROTOCOL_FILTERS)[number]

/** Whether an issue involves the selected protocol. "All" matches everything. */
export function issueMatches(issue: Issue, filter: string): boolean {
  if (filter === 'All') return true
  return issue.protocols?.includes(filter) ?? false
}

/** Whether a flow belongs to the selected protocol, as transport or application. */
export function flowMatches(flow: Flow, filter: string): boolean {
  if (filter === 'All') return true
  return flow.protocol === filter || flow.app_protocol === filter
}

/** Formats a byte count, for example "1.5 MB". */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

/** Formats a millisecond metric, or a dash if it was not measured. */
export function formatMs(ms: number): string {
  return ms > 0 ? `${ms.toLocaleString(undefined, { maximumFractionDigits: 1 })} ms` : '–'
}

/** Tailwind classes for a protocol's color: a dot, a bar segment and a badge. */
export function protocolColor(protocol: string): { dot: string; bar: string; badge: string } {
  switch (protocol) {
    case 'TCP':
      return { dot: 'bg-brand-500', bar: 'bg-brand-500', badge: 'bg-brand-50 dark:bg-brand-500/15 text-brand-600 dark:text-brand-400' }
    case 'UDP':
      return { dot: 'bg-blue-light-500', bar: 'bg-blue-light-500', badge: 'bg-blue-light-50 dark:bg-blue-light-500/15 text-blue-light-700 dark:text-blue-light-400' }
    case 'ICMP':
      return { dot: 'bg-warning-500', bar: 'bg-warning-500', badge: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400' }
    case 'ARP':
      return { dot: 'bg-success-500', bar: 'bg-success-500', badge: 'bg-success-50 dark:bg-success-500/15 text-success-700 dark:text-success-400' }
    case 'DNS':
      return { dot: 'bg-violet-500', bar: 'bg-violet-500', badge: 'bg-violet-50 dark:bg-violet-500/15 text-violet-700 dark:text-violet-400' }
    case 'HTTP':
      return { dot: 'bg-pink-500', bar: 'bg-pink-500', badge: 'bg-pink-50 dark:bg-pink-500/15 text-pink-700 dark:text-pink-400' }
    case 'QUIC':
      return { dot: 'bg-error-500', bar: 'bg-error-500', badge: 'bg-error-50 dark:bg-error-500/15 text-error-700 dark:text-error-400' }
    case 'DHCPv6':
      return { dot: 'bg-warning-500', bar: 'bg-warning-500', badge: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400' }
    case 'SIP':
      return { dot: 'bg-orange-500', bar: 'bg-orange-500', badge: 'bg-orange-50 dark:bg-orange-500/15 text-orange-700 dark:text-orange-400' }
    case 'TLS':
      return { dot: 'bg-teal-500', bar: 'bg-teal-500', badge: 'bg-teal-50 dark:bg-teal-500/15 text-teal-700 dark:text-teal-400' }
    default:
      return { dot: 'bg-gray-400', bar: 'bg-gray-400', badge: 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300' }
  }
}

/** Whether an issue describes the capture file, not the traffic. */
export function isCaptureNote(issue: Issue): boolean {
  return (NOTE_TITLES as readonly string[]).includes(issue.title)
}

/** The capture file extensions the analyzer accepts. */
export const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng']

/** Returns true if the file name ends in a supported capture extension. */
export function isCaptureFile(file: File): boolean {
  const name = file.name.toLowerCase()
  return ACCEPTED_EXTENSIONS.some((ext) => name.endsWith(ext))
}
