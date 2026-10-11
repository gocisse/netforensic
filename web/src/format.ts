import type { Issue, Severity } from './types'

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
