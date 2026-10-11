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
  if (score >= 80) return { label, text: 'text-success-600', ring: 'border-success-200', bg: 'bg-success-25', bar: 'bg-success-500' }
  if (score >= 40) return { label, text: 'text-warning-600', ring: 'border-warning-200', bg: 'bg-warning-25', bar: 'bg-warning-500' }
  return { label, text: 'text-error-600', ring: 'border-error-200', bg: 'bg-error-25', bar: 'bg-error-500' }
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 3, ERROR: 2, WARNING: 1, INFO: 0 }

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
export const NOTE_TITLES = ['Truncated Capture', 'Skipped Frames'] as const

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
export const PROTOCOL_FILTERS = ['All', 'TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'ARP', 'ICMP'] as const
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
      return { dot: 'bg-brand-500', bar: 'bg-brand-500', badge: 'bg-brand-50 text-brand-600' }
    case 'UDP':
      return { dot: 'bg-blue-light-500', bar: 'bg-blue-light-500', badge: 'bg-blue-light-50 text-blue-light-700' }
    case 'ICMP':
      return { dot: 'bg-warning-500', bar: 'bg-warning-500', badge: 'bg-warning-50 text-warning-700' }
    case 'ARP':
      return { dot: 'bg-success-500', bar: 'bg-success-500', badge: 'bg-success-50 text-success-700' }
    case 'DNS':
      return { dot: 'bg-violet-500', bar: 'bg-violet-500', badge: 'bg-violet-50 text-violet-700' }
    case 'HTTP':
      return { dot: 'bg-pink-500', bar: 'bg-pink-500', badge: 'bg-pink-50 text-pink-700' }
    case 'TLS':
      return { dot: 'bg-teal-500', bar: 'bg-teal-500', badge: 'bg-teal-50 text-teal-700' }
    default:
      return { dot: 'bg-gray-400', bar: 'bg-gray-400', badge: 'bg-gray-100 text-gray-700' }
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
