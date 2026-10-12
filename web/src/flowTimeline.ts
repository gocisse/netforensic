import { affectedOf } from './wireshark.ts'
import type { Flow, FlowEvent, Issue } from './types.ts'

/** A Wireshark display filter for the packets of a flow: its stream, or its addresses and ports if the stream number is unknown. */
export function flowFilter(f: Flow): string {
  if (f.tcp_stream !== undefined) return `tcp.stream eq ${f.tcp_stream}`
  const v6 = f.src_ip.includes(':') || f.dst_ip.includes(':')
  const addr = v6 ? 'ipv6.addr' : 'ip.addr'
  const proto = f.protocol.toLowerCase() === 'udp' ? 'udp' : 'tcp'
  return `${addr} == ${f.src_ip} && ${addr} == ${f.dst_ip} && ${proto}.port == ${f.src_port} && ${proto}.port == ${f.dst_port}`
}

/** The issues that name the flow (as its flow, target or an affected flow). */
export function issuesForFlow(issues: Issue[], f: Flow): Issue[] {
  return issues.filter((i) => affectedOf(i).some((a) => a.label === f.id))
}

/** Formats an ISO timestamp as "15:04:05.000" in UTC. */
export function clockTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toISOString().slice(11, 23)
}

/** How long after the first event another happened: "+0 ms", "+808 ms", "+1.250 s", "+2 min 5 s". */
export function sinceStart(iso: string, startIso: string): string {
  const ms = new Date(iso).getTime() - new Date(startIso).getTime()
  if (Number.isNaN(ms)) return ''
  if (ms < 1000) return `+${Math.max(0, Math.round(ms))} ms`
  if (ms < 60_000) return `+${(ms / 1000).toFixed(3)} s`
  return `+${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`
}

/** The first problem of a flow, if its timeline marks one. */
export function firstIssueOf(f: Flow): FlowEvent | undefined {
  return f.timeline?.find((e) => e.first_issue)
}

const STATUS_RANK: Record<string, number> = { broken: 2, slow: 1 }

/** The flows that have issues, the most broken first, then by issue count and size; at most `limit`. */
export function problemFlows(flows: Flow[], limit: number): Flow[] {
  return flows
    .filter((f) => (f.issue_count ?? 0) > 0)
    .sort(
      (a, b) =>
        (STATUS_RANK[b.status ?? ''] ?? 0) - (STATUS_RANK[a.status ?? ''] ?? 0) ||
        (b.issue_count ?? 0) - (a.issue_count ?? 0) ||
        b.packet_count - a.packet_count ||
        a.id.localeCompare(b.id),
    )
    .slice(0, limit)
}

/** How long a flow lasted, for display: "808 ms", "1.250 s", "2 min 5 s". */
export function flowDuration(f: Flow): string {
  return sinceStart(f.end_time, f.start_time).replace(/^\+/, '')
}
