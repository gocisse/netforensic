import { severityRank } from './format.ts'
import type { Issue, Severity } from './types.ts'
import { affectedOf } from './wireshark.ts'

/** A severity and the issues of it. */
export interface SeverityGroup {
  severity: Severity
  issues: Issue[]
}

/**
 * Groups issues by severity, the worst first (CRITICAL, ERROR, WARNING,
 * INFO), leaving out the severities with no issues. Within a group the issues
 * with the most events come first.
 */
export function groupBySeverity(issues: Issue[]): SeverityGroup[] {
  const by = new Map<Severity, Issue[]>()
  for (const i of issues) by.set(i.severity, [...(by.get(i.severity) ?? []), i])
  return [...by.entries()]
    .sort((a, b) => severityRank(b[0]) - severityRank(a[0]))
    .map(([severity, list]) => ({
      severity,
      issues: list.sort((a, b) => (b.count ?? 1) - (a.count ?? 1) || a.title.localeCompare(b.title)),
    }))
}

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`

/**
 * Says how much an issue touches: its events and the flows (pairs of
 * addresses) and other names (hosts, domains) they name. An issue that names
 * nothing is described by its events alone.
 */
export function impactOf(issue: Issue): string {
  const events = Math.max(issue.count ?? 0, issue.occurrences?.length ?? 0, 1)
  const affected = affectedOf(issue)
  const flows = affected.filter((a) => a.endpoints.length === 2).length
  const others = affected.length - flows
  const parts: string[] = []
  if (flows > 0) parts.push(plural(flows, 'flow'))
  if (others > 0) parts.push(plural(others, 'other target'))
  const events_ = plural(events, 'event')
  return parts.length > 0 ? `${events_} across ${parts.join(' and ')}` : events_
}
