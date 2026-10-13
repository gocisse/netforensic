import { ipKey } from '../filters/ip.ts'
import { parseRef } from '../filters/refs.ts'
import type { Flow, Issue, Severity, Topology, TopologyEdge, TopologyNode } from '../types.ts'

/** The color class of a node: red for an address with issues, yellow for one with a lot of traffic, green for the rest. */
export type Tone = 'problem' | 'busy' | 'ok'

/** Radii of a node in px, before zooming: the least busy and the busiest. */
export const MIN_RADIUS = 5
export const MAX_RADIUS = 24

/** How big a node is: its radius grows with the square root of its share of the busiest node's traffic. */
export function nodeRadius(volume: number, maxVolume: number): number {
  if (maxVolume <= 0 || volume <= 0) return MIN_RADIUS
  return MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) * Math.sqrt(Math.min(volume / maxVolume, 1))
}

/** How thick an edge is in px: 1 for the quietest, 6 for the busiest. */
export function edgeWidth(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0 || bytes <= 0) return 1
  return 1 + 5 * Math.sqrt(Math.min(bytes / maxBytes, 1))
}

/**
 * The traffic above which a node counts as busy: that of the busiest tenth of
 * the nodes. A graph of fewer than five nodes has no busy ones; Infinity says so.
 */
export function busyThreshold(nodes: TopologyNode[]): number {
  if (nodes.length < 5) return Infinity
  const volumes = nodes.map((n) => n.traffic_volume).sort((a, b) => b - a)
  return volumes[Math.ceil(nodes.length / 10) - 1]
}

/** The tone of a node: issues first, then heavy traffic. */
export function nodeTone(node: TopologyNode, busy: number): Tone {
  if (node.is_problematic) return 'problem'
  return node.traffic_volume >= busy && node.traffic_volume > 0 ? 'busy' : 'ok'
}

/** The colors of the tones, for the light and the dark theme. */
export const TONE_COLORS: Record<Tone, { light: string; dark: string }> = {
  problem: { light: '#d92d20', dark: '#f97066' },
  busy: { light: '#f79009', dark: '#fdb022' },
  ok: { light: '#12b76a', dark: '#32d583' },
}

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'ERROR', 'WARNING', 'INFO']

/** What the filters of the diagram let through: the protocols and the worst severities of issues. */
export interface TopologyFilter {
  /** Protocols whose edges are shown. */
  protocols: ReadonlySet<string>
  /** Severities of edges with issues that are shown; an edge without issues is not affected. */
  severities: ReadonlySet<Severity>
}

/** The protocols the edges of a topology carry, by number of edges, the most first. */
export function edgeProtocols(topo: Topology): { protocol: string; edges: number }[] {
  const counts = new Map<string, number>()
  for (const e of topo.edges) counts.set(e.protocol || 'Other', (counts.get(e.protocol || 'Other') ?? 0) + 1)
  return [...counts.entries()].map(([protocol, edges]) => ({ protocol, edges })).sort((a, b) => b.edges - a.edges || a.protocol.localeCompare(b.protocol))
}

/** The severities the edges with issues have, the worst first. */
export function edgeSeverities(topo: Topology): Severity[] {
  const seen = new Set<Severity>()
  for (const e of topo.edges) if (e.issues > 0 && e.worst_severity) seen.add(e.worst_severity)
  return SEVERITY_ORDER.filter((s) => seen.has(s))
}

/** Whether an edge passes the filter. */
export function edgeVisible(e: TopologyEdge, f: TopologyFilter): boolean {
  if (!f.protocols.has(e.protocol || 'Other')) return false
  return e.issues === 0 || !e.worst_severity || f.severities.has(e.worst_severity)
}

/**
 * Which nodes and edges the filter shows. An edge is shown if it passes the
 * filter; a node is shown if an edge it is on is, or if it has none at all.
 */
export function visibleParts(topo: Topology, f: TopologyFilter): { nodes: Set<string>; edges: Set<TopologyEdge> } {
  const edges = new Set<TopologyEdge>()
  const touched = new Set<string>()
  const hasEdge = new Set<string>()
  for (const e of topo.edges) {
    hasEdge.add(e.source)
    hasEdge.add(e.target)
    if (edgeVisible(e, f)) {
      edges.add(e)
      touched.add(e.source)
      touched.add(e.target)
    }
  }
  const nodes = new Set<string>()
  for (const n of topo.nodes) if (touched.has(n.ip) || !hasEdge.has(n.ip)) nodes.add(n.ip)
  return { nodes, edges }
}

/** Whether a node matches a search: the text is part of its address (or of its role). */
export function nodeMatches(node: TopologyNode, query: string): boolean {
  const q = query.trim().toLowerCase()
  return q !== '' && (node.ip.toLowerCase().includes(q) || node.type.replace('_', ' ').includes(q))
}

/** The issues that name an address: by their flow, their target or the subjects of their events. */
export function issuesForIp(issues: Issue[], ip: string): Issue[] {
  const want = ipKey(ip)
  if (want === null) return []
  const names = (ref: string | undefined) => parseRef(ref).some((e) => e.ip === want)
  return issues.filter((i) => names(i.flow_id) || names(i.target) || (i.occurrences ?? []).some((o) => names(o.subject)))
}

/**
 * Whether the diagram is worth showing: the capture has issues, or one address
 * carries a large part of the traffic (a quarter or more of all the bytes), such
 * as a DNS server asked by everybody. Fewer than three flows are never worth it.
 */
export function worthShowing(issueCount: number, flows: Flow[]): boolean {
  if (issueCount > 0) return true
  if (flows.length < 3) return false
  const per = new Map<string, number>()
  let total = 0
  for (const f of flows) {
    const b = f.bytes_sent + f.bytes_recv
    total += b
    per.set(f.src_ip, (per.get(f.src_ip) ?? 0) + b)
    per.set(f.dst_ip, (per.get(f.dst_ip) ?? 0) + b)
  }
  if (total === 0) return false
  // every byte is counted at both ends, so an address on every flow holds all of total
  return Math.max(...per.values()) / total >= 0.25
}

/** What part of the world the canvas shows: the world point at its top left, and the zoom (px per world unit). */
export interface View {
  x: number
  y: number
  k: number
}

export const MIN_ZOOM = 0.05
export const MAX_ZOOM = 8

/** Zooms by a factor around a screen point, so that the point stays where it is. */
export function zoomAt(v: View, factor: number, sx: number, sy: number): View {
  const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.k * factor))
  if (k === v.k) return v
  const wx = v.x + sx / v.k
  const wy = v.y + sy / v.k
  return { k, x: wx - sx / k, y: wy - sy / k }
}

/** The view that shows the box of the points (with a margin) in a canvas, and never magnifies beyond 2. */
export function fitView(points: { x: number; y: number; r: number }[], width: number, height: number, margin = 48): View {
  if (points.length === 0 || width <= 0 || height <= 0) return { x: 0, y: 0, k: 1 }
  let minX = Infinity
  let minY = Infinity
  let maxX = -Infinity
  let maxY = -Infinity
  for (const p of points) {
    minX = Math.min(minX, p.x - p.r)
    minY = Math.min(minY, p.y - p.r)
    maxX = Math.max(maxX, p.x + p.r)
    maxY = Math.max(maxY, p.y + p.r)
  }
  const w = Math.max(maxX - minX, 1)
  const h = Math.max(maxY - minY, 1)
  const k = Math.min(2, Math.max(MIN_ZOOM, Math.min((width - 2 * margin) / w, (height - 2 * margin) / h)))
  return { k, x: (minX + maxX) / 2 - width / 2 / k, y: (minY + maxY) / 2 - height / 2 / k }
}

/** Whether a circle is at least partly inside the canvas: the test that lets the diagram skip what is out of sight. */
export function circleInView(x: number, y: number, r: number, v: View, width: number, height: number): boolean {
  const sx = (x - v.x) * v.k
  const sy = (y - v.y) * v.k
  const sr = r * v.k
  return sx + sr >= 0 && sy + sr >= 0 && sx - sr <= width && sy - sr <= height
}

/** Whether the bounding box of a line segment meets the canvas. */
export function segmentInView(x1: number, y1: number, x2: number, y2: number, v: View, width: number, height: number): boolean {
  const ax = (x1 - v.x) * v.k
  const ay = (y1 - v.y) * v.k
  const bx = (x2 - v.x) * v.k
  const by = (y2 - v.y) * v.k
  return !(Math.max(ax, bx) < 0 || Math.min(ax, bx) > width || Math.max(ay, by) < 0 || Math.min(ay, by) > height)
}

/** The node under a screen point, the nearest if several are, or -1. Radii are in world units. */
export function hitTest(xs: ArrayLike<number>, ys: ArrayLike<number>, rs: ArrayLike<number>, visible: (i: number) => boolean, v: View, sx: number, sy: number): number {
  const wx = v.x + sx / v.k
  const wy = v.y + sy / v.k
  let best = -1
  let bestDist = Infinity
  for (let i = 0; i < xs.length; i++) {
    if (!visible(i)) continue
    const dx = wx - xs[i]
    const dy = wy - ys[i]
    // a node is always at least 8 px wide on the screen, so that a small one can be hit
    const r = Math.max(rs[i], 8 / v.k)
    const d = dx * dx + dy * dy
    if (d <= r * r && d < bestDist) {
      best = i
      bestDist = d
    }
  }
  return best
}

/** Formats bytes for a tooltip: 1.5 MB. */
export function formatVolume(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = bytes
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}
