import type { Flow } from './types.ts'

export type GoodSortKey = 'flow' | 'packets' | 'bytes' | 'rtt' | 'protocol' | 'status'
export type SortDir = 'asc' | 'desc'

/** Whether a flow matches a search for an address, a port or a protocol; every word must match. */
export function matchesGoodSearch(f: Flow, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return true
  const hay = [f.src_ip, f.dst_ip, `${f.src_ip}:${f.src_port}`, `${f.dst_ip}:${f.dst_port}`, String(f.src_port), String(f.dst_port), f.protocol, f.app_protocol ?? '']
    .join(' ')
    .toLowerCase()
  return words.every((w) => hay.includes(w))
}

const value = (f: Flow, key: GoodSortKey): number | string => {
  switch (key) {
    case 'flow':
      return f.id
    case 'packets':
      return f.packet_count
    case 'bytes':
      return f.bytes_sent + f.bytes_recv
    case 'rtt':
      return f.avg_rtt_ms
    case 'protocol':
      return f.app_protocol || f.protocol || ''
    default:
      return f.status === 'slow' || f.status === 'broken' ? 1 : 0
  }
}

/** Sorts flows by a column; ties go to the busier flow, then to the ID, so the order is stable. */
export function sortGoodFlows(flows: Flow[], key: GoodSortKey, dir: SortDir): Flow[] {
  const sign = dir === 'asc' ? 1 : -1
  return [...flows].sort((a, b) => {
    const x = value(a, key)
    const y = value(b, key)
    const c = typeof x === 'string' && typeof y === 'string' ? x.localeCompare(y) : (x as number) - (y as number)
    return c * sign || b.packet_count - a.packet_count || a.id.localeCompare(b.id)
  })
}
