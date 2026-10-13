import { displayIP } from './filters/ip.ts'
import { parseRef } from './filters/refs.ts'
import type { Endpoint } from './filters/refs.ts'
import { severityRank } from './format.ts'
import type { SortDir } from './goodTraffic.ts'
import type { Issue } from './types.ts'
import { affectedOf } from './wireshark.ts'

/** The columns the issues table sorts by. */
export type IssueSortKey = 'severity' | 'title' | 'count' | 'ips' | 'protocol'

const eventCount = (i: Issue) => Math.max(i.count ?? 1, 1)

/** The order of the table when no column is chosen: the worst severity first, then the most events, then by title. */
function byDefault(a: Issue, b: Issue): number {
  return severityRank(b.severity) - severityRank(a.severity) || eventCount(b) - eventCount(a) || a.title.localeCompare(b.title)
}

/** The protocol column of an issue: the one it is most about (the first it names), or "". */
export const issueProtocol = (i: Issue): string => i.protocols?.[0] ?? ''

/**
 * Sorts issues by a column; issues that tie keep the default order (worst
 * severity, then most events). The input is left as it is.
 */
export function sortIssues(issues: Issue[], key: IssueSortKey, dir: SortDir): Issue[] {
  const sign = dir === 'asc' ? 1 : -1
  // The text of the addresses is costly to build, so it is built once per issue.
  const text = key === 'ips' ? new Map(issues.map((i) => [i, affectedIPs(i).labels.join(' ')])) : null
  const primary = (a: Issue, b: Issue): number => {
    switch (key) {
      case 'severity':
        return severityRank(a.severity) - severityRank(b.severity)
      case 'count':
        return eventCount(a) - eventCount(b)
      case 'title':
        return a.title.localeCompare(b.title)
      case 'protocol':
        return issueProtocol(a).localeCompare(issueProtocol(b))
      default:
        return (text?.get(a) ?? '').localeCompare(text?.get(b) ?? '')
    }
  }
  return [...issues].sort((a, b) => sign * primary(a, b) || byDefault(a, b))
}

/** Whether an issue matches a search; every word must be found in its severity, title, description, category, protocols, flow, target or the subjects of its events. */
export function matchesIssueSearch(issue: Issue, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return true
  const parts = [issue.severity, issue.title, issue.description, issue.category, (issue.protocols ?? []).join(' '), issue.flow_id ?? '', issue.target ?? '']
  for (const o of issue.occurrences ?? []) parts.push(o.subject)
  const hay = parts.join(' ').toLowerCase()
  return words.every((w) => hay.includes(w))
}

/** The addresses an issue is about, as the table shows them. */
export interface AffectedIPs {
  /** The first few, ready to show: "a:1 → b:2" for a flow, "a:1" for an address, a name as it is. */
  labels: string[]
  /** How many there are in all. */
  total: number
}

const ENDPOINT = String.raw`(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])(?::\d{1,5})?`
const ADDRESSES_IN_TEXT = new RegExp(`${ENDPOINT}(?:-${ENDPOINT})?`, 'g')

const endpointText = (e: Endpoint): string => {
  const ip = displayIP(e.ip)
  if (e.port <= 0) return ip
  return ip.includes(':') ? `[${ip}]:${e.port}` : `${ip}:${e.port}`
}

/** Writes a reference to a flow or an address for the table; a name that is not an address stays as it is. */
function refText(label: string): string {
  const eps = parseRef(label)
  if (eps.length === 2) return `${endpointText(eps[0])} \u2192 ${endpointText(eps[1])}`
  if (eps.length === 1) return endpointText(eps[0])
  return label
}

/**
 * Says which addresses an issue is about: its flow, its target and the
 * subjects of its events, each once (a target that is an end of a flow already
 * named is left out). An issue that names none of them in its fields is read
 * for the addresses in its description. At most `shown` are returned as
 * labels; `total` counts them all.
 */
export function affectedIPs(issue: Issue, shown = 2): AffectedIPs {
  const key = (e: Endpoint) => `${e.ip}|${e.port}`
  let items = affectedOf(issue)
  const inFlows = new Set(items.filter((a) => a.endpoints.length === 2).flatMap((a) => a.endpoints.map(key)))
  items = items.filter((a) => !(a.endpoints.length === 1 && inFlows.has(key(a.endpoints[0]))))
  let refs = items.map((a) => a.label)
  if (refs.length === 0) refs = [...new Set((issue.description.match(ADDRESSES_IN_TEXT) ?? []).filter((m) => parseRef(m).length > 0))]
  return { labels: refs.slice(0, shown).map(refText), total: refs.length }
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
