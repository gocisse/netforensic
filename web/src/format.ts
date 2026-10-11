import type { Flow, Issue, Occurrence, Severity } from './types'

export interface Tone {
  label: string
  /** Tailwind classes for the score number. */
  text: string
  /** Tailwind classes for the ring/background. */
  ring: string
  bg: string
}

/**
 * Colors the health score: green from 80, yellow from 40, red below that
 * (including negative scores). The label follows the CLI's bands.
 */
export function healthTone(score: number): Tone {
  const label =
    score >= 90 ? 'Healthy' : score >= 70 ? 'Degraded' : score >= 40 ? 'Unhealthy' : score >= 0 ? 'Critical' : 'Catastrophic'
  if (score >= 80) return { label, text: 'text-green-700', ring: 'border-green-500', bg: 'bg-green-50' }
  if (score >= 40) return { label, text: 'text-yellow-700', ring: 'border-yellow-500', bg: 'bg-yellow-50' }
  return { label, text: 'text-red-700', ring: 'border-red-500', bg: 'bg-red-50' }
}

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 3, ERROR: 2, WARNING: 1, INFO: 0 }

export function severityBadge(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
    case 'ERROR':
      return 'bg-red-100 text-red-800'
    case 'WARNING':
      return 'bg-yellow-100 text-yellow-800'
    default:
      return 'bg-sky-100 text-sky-800'
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

/** Tailwind classes for a protocol's color. */
export function protocolColor(protocol: string): { dot: string; bar: string; badge: string } {
  switch (protocol) {
    case 'TCP':
      return { dot: 'bg-indigo-500', bar: 'bg-indigo-500', badge: 'bg-indigo-50 text-indigo-800' }
    case 'UDP':
      return { dot: 'bg-sky-500', bar: 'bg-sky-500', badge: 'bg-sky-50 text-sky-800' }
    case 'ICMP':
      return { dot: 'bg-amber-500', bar: 'bg-amber-500', badge: 'bg-amber-50 text-amber-800' }
    case 'ARP':
      return { dot: 'bg-emerald-500', bar: 'bg-emerald-500', badge: 'bg-emerald-50 text-emerald-800' }
    case 'DNS':
      return { dot: 'bg-violet-500', bar: 'bg-violet-500', badge: 'bg-violet-50 text-violet-800' }
    case 'HTTP':
      return { dot: 'bg-rose-500', bar: 'bg-rose-500', badge: 'bg-rose-50 text-rose-800' }
    case 'TLS':
      return { dot: 'bg-teal-500', bar: 'bg-teal-500', badge: 'bg-teal-50 text-teal-800' }
    default:
      return { dot: 'bg-slate-400', bar: 'bg-slate-400', badge: 'bg-slate-100 text-slate-700' }
  }
}
