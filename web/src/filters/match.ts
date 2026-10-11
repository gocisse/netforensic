import type { Flow, Issue, ProtocolStat } from '../types'
import { ipKey } from './ip'
import type { ParsedFilters } from './model'
import { portIn } from './ports'
import { parseRef } from './refs'
import type { Endpoint } from './refs'

/*
 * The rules below are the same as in the server's package filter, which
 * applies them to /api/export-csv, so that an export holds exactly what the
 * page shows:
 *
 * Flows are bidirectional, so an IP filter matches either endpoint. An issue
 * is tied to addresses and ports through what it refers to: its flow, its
 * target and the subjects of its events. An issue that refers to no address
 * does not match an IP or port filter.
 */

function hasEndpointFilter(f: ParsedFilters): boolean {
  return f.sourceIp !== '' || f.destIp !== '' || f.ports.length > 0
}

/** Whether the endpoints satisfy the IP and port filters. */
function involves(f: ParsedFilters, eps: Endpoint[]): boolean {
  if (f.sourceIp !== '' && !eps.some((e) => e.ip === f.sourceIp)) return false
  if (f.destIp !== '' && !eps.some((e) => e.ip === f.destIp)) return false
  if (f.ports.length > 0 && !eps.some((e) => e.port !== 0 && portIn(f.ports, e.port))) return false
  return true
}

const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()

/** Whether a flow passes the IP, port and protocol filters. */
export function matchFlow(f: ParsedFilters, flow: Flow): boolean {
  if (f.protocol !== '') {
    const byProtocol = eq(flow.protocol, f.protocol) || eq(flow.app_protocol ?? '', f.protocol) || (flow.protocol === '' && eq(f.protocol, 'Other'))
    if (!byProtocol) return false
  }
  if (!hasEndpointFilter(f)) return true
  const eps: Endpoint[] = []
  for (const [ip, port] of [
    [flow.src_ip, flow.src_port],
    [flow.dst_ip, flow.dst_port],
  ] as const) {
    const key = ipKey(ip)
    if (key !== null) eps.push({ ip: key, port })
  }
  return involves(f, eps)
}

/** The addresses an issue refers to. */
function issueEndpoints(issue: Issue): Endpoint[] {
  const refs = [issue.flow_id, issue.target, ...(issue.occurrences ?? []).map((o) => o.subject)]
  return refs.flatMap((r) => parseRef(r))
}

/** Whether an issue passes all the filters. Capture notes are not matched here: the page leaves them out first. */
export function matchIssue(f: ParsedFilters, issue: Issue): boolean {
  if (f.severities.length > 0 && !f.severities.includes(issue.severity)) return false
  if (f.categories.length > 0 && !f.categories.some((c) => eq(c, issue.category))) return false
  if (f.protocol !== '' && !(issue.protocols ?? []).some((p) => eq(p, f.protocol))) return false
  if (!hasEndpointFilter(f)) return true
  return involves(f, issueEndpoints(issue))
}

/**
 * The protocol distribution of flows: packets, flows and share of the packets
 * per protocol, most packets first. Every flow counts towards its transport
 * protocol (an unnamed one is "Other") and also towards its application
 * protocol, so the application protocols overlap the transport ones.
 */
export function protocolStats(flows: Flow[]): ProtocolStat[] {
  const by = new Map<string, { layer: 'transport' | 'application'; packets: number; flows: number }>()
  let total = 0
  const add = (name: string, layer: 'transport' | 'application', packets: number) => {
    const a = by.get(name) ?? { layer, packets: 0, flows: 0 }
    a.packets += packets
    a.flows += 1
    by.set(name, a)
  }
  for (const f of flows) {
    total += f.packet_count
    add(f.protocol === '' ? 'Other' : f.protocol, 'transport', f.packet_count)
    if (f.app_protocol) add(f.app_protocol, 'application', f.packet_count)
  }
  return [...by.entries()]
    .map(([protocol, a]) => ({
      protocol,
      layer: a.layer,
      packets: a.packets,
      flows: a.flows,
      percent: total > 0 ? Math.round((a.packets * 1000) / total) / 10 : 0,
      top_flows: [],
    }))
    .sort((a, b) => b.packets - a.packets || (a.protocol < b.protocol ? -1 : a.protocol > b.protocol ? 1 : 0))
}

/** The bytes of a flow in both directions. */
export const flowBytes = (f: Flow) => f.bytes_sent + f.bytes_recv

/** A flow's worst timing metric, as the analysis ranks the slowest flows. */
export const worstTiming = (f: Flow) => Math.max(f.setup_time_ms, f.ttfb_ms, f.max_rtt_ms)

/** An address's share of the traffic: the bytes of every flow it is in. */
export interface Talker {
  ip: string
  bytes: number
  packets: number
  flows: number
}

/** The busiest addresses by bytes, over flows. */
export function topTalkers(flows: Flow[], n: number): Talker[] {
  const by = new Map<string, Talker>()
  for (const f of flows) {
    for (const ip of new Set([f.src_ip, f.dst_ip])) {
      const t = by.get(ip) ?? { ip, bytes: 0, packets: 0, flows: 0 }
      t.bytes += flowBytes(f)
      t.packets += f.packet_count
      t.flows += 1
      by.set(ip, t)
    }
  }
  return [...by.values()].sort((a, b) => b.bytes - a.bytes || (a.ip < b.ip ? -1 : 1)).slice(0, n)
}
