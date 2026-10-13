import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ForceLayout } from '../topology/layout'
import {
  TONE_COLORS,
  busyThreshold,
  circleInView,
  edgeWidth,
  fitView,
  formatVolume,
  hitTest,
  nodeMatches,
  nodeRadius,
  nodeTone,
  segmentInView,
  visibleParts,
  zoomAt,
} from '../topology/model'
import type { TopologyFilter, View } from '../topology/model'
import type { Topology } from '../types'

/** The height of the canvas in px. */
const HEIGHT = 560
/** Ticks of the layout run before the first picture, and the time one animation frame may spend on more. */
const FIRST_TICKS = 80
const FRAME_BUDGET_MS = 8

export interface Props {
  topology: Topology
  filter: TopologyFilter
  /** Nodes whose address (or role) contains this text are highlighted, the rest dimmed. */
  search: string
  /** Changes when the view should be fitted to the diagram again. */
  resetToken: number
  /** Called with the address of a node that is clicked. */
  onSelect: (ip: string) => void
}

interface Hover {
  index: number
  /** Where the tooltip goes, in px from the top left of the canvas. */
  left: number
  top: number
}

/** What a test or a debugger can read from the canvas: where the nodes are on the screen, and the view. */
export interface TopologyState {
  nodes: { ip: string; x: number; y: number; r: number; tone: string; visible: boolean; drawn: boolean }[]
  view: View
  settled: boolean
}

const isDark = () => document.documentElement.classList.contains('dark')

/**
 * The network as a graph on a canvas: a force-directed layout of the addresses
 * (circles, sized by traffic and red, yellow or green) and the traffic between
 * them (lines, as thick as the traffic, red if they have issues, with an arrow
 * toward the receiver). The mouse wheel zooms around the pointer, a drag pans,
 * hovering a node shows its details and a click selects it. Only what is in
 * view is drawn, and drawing is done at most once per animation frame.
 */
export default function NetworkTopology({ topology, filter, search, resetToken, onSelect }: Props) {
  const box = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const [hover, setHover] = useState<Hover | null>(null)
  const [panning, setPanning] = useState(false)

  // What the diagram is made of: nodes (busiest first, as the server sends them), their sizes and tones, and the edges by node index.
  const model = useMemo(() => {
    const nodes = topology.nodes
    const index = new Map(nodes.map((n, i) => [n.ip, i]))
    const maxVolume = Math.max(0, ...nodes.map((n) => n.traffic_volume))
    const maxBytes = Math.max(0, ...topology.edges.map((e) => e.bytes))
    const busy = busyThreshold(nodes)
    const radii = nodes.map((n) => nodeRadius(n.traffic_volume, maxVolume))
    const tones = nodes.map((n) => nodeTone(n, busy))
    const edges = topology.edges
      .map((e) => ({ e, a: index.get(e.source) ?? -1, b: index.get(e.target) ?? -1, width: edgeWidth(e.bytes, maxBytes) }))
      .filter((x) => x.a >= 0 && x.b >= 0)
    return { nodes, index, radii, tones, edges }
  }, [topology])

  const layout = useMemo(() => new ForceLayout(model.radii, model.edges.map((x) => ({ a: x.a, b: x.b }))), [model])

  const visible = useMemo(() => visibleParts(topology, filter), [topology, filter])
  const matches = useMemo(() => (search.trim() === '' ? null : new Set(model.nodes.filter((n) => nodeMatches(n, search)).map((n) => n.ip))), [model, search])

  // Everything the drawing needs, in refs: the drawing runs outside React's render.
  const view = useRef<View>({ x: 0, y: 0, k: 1 })
  const size = useRef({ width: 0, height: HEIGHT, dpr: 1 })
  const live = useRef({ model, layout, visible, matches, hover: -1 })
  const hoverIndex = hover?.index ?? -1
  useEffect(() => {
    live.current = { model, layout, visible, matches, hover: hoverIndex }
  })
  const frame = useRef(0)
  const drawn = useRef(0)

  const draw = useCallback(() => {
    frame.current = 0
    const el = canvas.current
    const ctx = el?.getContext('2d')
    if (!el || !ctx) return
    const { model: m, layout: l, visible: vis, matches: found, hover: hov } = live.current
    const { width, height, dpr } = size.current
    const v = view.current
    const dark = isDark()
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, width, height)
    ctx.lineCap = 'round'
    const sx = (x: number) => (x - v.x) * v.k
    const sy = (y: number) => (y - v.y) * v.k

    const quiet = dark ? 'rgba(152,162,179,0.55)' : 'rgba(102,112,133,0.5)'
    const alarm = dark ? '#f97066' : '#d92d20'
    for (const { e, a, b, width: w } of m.edges) {
      if (!vis.edges.has(e)) continue
      if (!segmentInView(l.x[a], l.y[a], l.x[b], l.y[b], v, width, height)) continue
      const dim = found !== null && !found.has(e.source) && !found.has(e.target)
      const x1 = sx(l.x[a]), y1 = sy(l.y[a]), x2 = sx(l.x[b]), y2 = sy(l.y[b])
      const dx = x2 - x1, dy = y2 - y1
      const d = Math.hypot(dx, dy)
      if (d < 1) continue
      const ux = dx / d, uy = dy / d
      const rb = l.r[b] * v.k
      const color = e.issues > 0 ? alarm : quiet
      ctx.globalAlpha = dim ? 0.15 : 1
      ctx.strokeStyle = color
      ctx.fillStyle = color
      ctx.lineWidth = w
      ctx.beginPath()
      ctx.moveTo(x1, y1)
      ctx.lineTo(x2 - ux * rb, y2 - uy * rb)
      ctx.stroke()
      // the arrowhead touches the receiver's rim
      const head = 5 + w * 1.5
      const tx = x2 - ux * rb, ty = y2 - uy * rb
      ctx.beginPath()
      ctx.moveTo(tx, ty)
      ctx.lineTo(tx - ux * head - uy * head * 0.5, ty - uy * head + ux * head * 0.5)
      ctx.lineTo(tx - ux * head + uy * head * 0.5, ty - uy * head - ux * head * 0.5)
      ctx.closePath()
      ctx.fill()
    }

    let count = 0
    const labelColor = dark ? '#e4e7ec' : '#1d2939'
    ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace'
    ctx.textAlign = 'center'
    for (let i = 0; i < m.nodes.length; i++) {
      const n = m.nodes[i]
      if (!vis.nodes.has(n.ip)) continue
      if (!circleInView(l.x[i], l.y[i], l.r[i] + 4, v, width, height)) continue
      count++
      const x = sx(l.x[i]), y = sy(l.y[i]), r = Math.max(l.r[i] * v.k, 3)
      const match = found?.has(n.ip) ?? false
      ctx.globalAlpha = found !== null && !match ? 0.25 : 1
      ctx.fillStyle = TONE_COLORS[m.tones[i]][dark ? 'dark' : 'light']
      ctx.beginPath()
      ctx.arc(x, y, r, 0, Math.PI * 2)
      ctx.fill()
      if (match || i === hov) {
        ctx.lineWidth = 3
        ctx.strokeStyle = dark ? '#9cb9ff' : '#3641f5'
        ctx.beginPath()
        ctx.arc(x, y, r + 4, 0, Math.PI * 2)
        ctx.stroke()
      }
      if (match || i === hov || r >= 12 || v.k >= 1.2) {
        ctx.fillStyle = labelColor
        ctx.fillText(n.ip, x, y + r + 14)
      }
    }
    ctx.globalAlpha = 1
    drawn.current = count
    el.dataset.zoom = v.k.toFixed(3)
    el.dataset.drawnNodes = String(count)
  }, [])

  // At most one drawing per animation frame, however many things ask for one.
  const requestDraw = useCallback(() => {
    if (frame.current === 0) frame.current = requestAnimationFrame(draw)
  }, [draw])

  const fit = useCallback(() => {
    const l = live.current.layout
    const { width, height } = size.current
    const points = live.current.model.nodes
      .map((n, i) => ({ x: l.x[i], y: l.y[i], r: l.r[i], show: live.current.visible.nodes.has(n.ip) }))
      .filter((p) => p.show)
    view.current = fitView(points, width, height)
    requestDraw()
  }, [requestDraw])

  // Size the canvas to its box, sharp on high-density screens.
  useEffect(() => {
    const el = canvas.current
    const parent = box.current
    if (!el || !parent) return
    const resize = () => {
      const width = parent.clientWidth
      const dpr = window.devicePixelRatio || 1
      size.current = { width, height: HEIGHT, dpr }
      el.width = Math.round(width * dpr)
      el.height = Math.round(HEIGHT * dpr)
      el.style.width = `${width}px`
      el.style.height = `${HEIGHT}px`
      requestDraw()
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(parent)
    const mo = new MutationObserver(requestDraw) // the theme changes the colors
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => {
      ro.disconnect()
      mo.disconnect()
      if (frame.current) cancelAnimationFrame(frame.current)
      frame.current = 0
    }
  }, [requestDraw])

  // Lay the graph out: a first run before the first picture, then a few ticks per frame until it settles.
  const settled = useRef(false)
  useEffect(() => {
    settled.current = false
    for (let i = 0; i < FIRST_TICKS && !layout.tick(); i++);
    fit()
    let raf = 0
    const run = () => {
      const t0 = performance.now()
      let done = layout.done
      while (!done && performance.now() - t0 < FRAME_BUDGET_MS) done = layout.tick()
      if (done) {
        settled.current = true
        fit()
        if (canvas.current) canvas.current.dataset.settled = 'true'
        return
      }
      requestDraw()
      raf = requestAnimationFrame(run)
    }
    if (canvas.current) canvas.current.dataset.settled = 'false'
    raf = requestAnimationFrame(run)
    return () => cancelAnimationFrame(raf)
  }, [layout, fit, requestDraw])

  // Filters and search change what is drawn; the Reset View button refits.
  useEffect(requestDraw, [visible, matches, hoverIndex, requestDraw])
  useEffect(() => {
    if (resetToken > 0) fit()
  }, [resetToken, fit])

  // The wheel zooms around the pointer. React attaches wheel listeners as passive, which cannot stop the page from scrolling.
  useEffect(() => {
    const el = canvas.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const rect = el.getBoundingClientRect()
      view.current = zoomAt(view.current, Math.exp(-e.deltaY * 0.0015), e.clientX - rect.left, e.clientY - rect.top)
      requestDraw()
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [requestDraw])

  // Drag to pan; a press that does not move is a click.
  const press = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null)
  const pointer = useRef<{ x: number; y: number } | null>(null)
  const pending = useRef(0)

  const nodeAt = (x: number, y: number) => {
    const { layout: l, visible: vis, model: m } = live.current
    return hitTest(l.x, l.y, l.r, (i) => vis.nodes.has(m.nodes[i].ip), view.current, x, y)
  }
  const local = (e: React.PointerEvent) => {
    const rect = e.currentTarget.getBoundingClientRect()
    return { x: e.clientX - rect.left, y: e.clientY - rect.top }
  }

  const onPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const p = local(e)
    press.current = { x: p.x, y: p.y, vx: view.current.x, vy: view.current.y, moved: false }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const p = local(e)
    pointer.current = p
    const start = press.current
    if (start) {
      if (!start.moved && Math.hypot(p.x - start.x, p.y - start.y) > 3) start.moved = true
      if (start.moved) {
        setPanning(true)
        view.current = { ...view.current, x: start.vx - (p.x - start.x) / view.current.k, y: start.vy - (p.y - start.y) / view.current.k }
        setHover(null)
        requestDraw()
        return
      }
    }
    // hovering is worked out once per frame, however fast the mouse moves
    if (pending.current === 0) {
      pending.current = requestAnimationFrame(() => {
        pending.current = 0
        const q = pointer.current
        if (!q) return
        const i = nodeAt(q.x, q.y)
        const { width } = size.current
        setHover(i < 0 ? null : { index: i, left: Math.min(q.x + 16, Math.max(width - 240, 0)), top: Math.min(q.y + 16, HEIGHT - 120) })
      })
    }
  }
  const onPointerUp = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const start = press.current
    press.current = null
    setPanning(false)
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId)
    if (start && !start.moved) {
      const i = nodeAt(start.x, start.y)
      if (i >= 0) onSelect(model.nodes[i].ip)
    }
  }
  const onPointerLeave = () => {
    pointer.current = null
    setHover(null)
  }
  useEffect(() => () => cancelAnimationFrame(pending.current), [])

  // A hook for tests and debugging: where everything is on the screen.
  useEffect(() => {
    const el = canvas.current as (HTMLCanvasElement & { topologyState?: () => TopologyState }) | null
    if (!el) return
    el.topologyState = () => {
      const { layout: l, model: m, visible: vis } = live.current
      const v = view.current
      const { width, height } = size.current
      return {
        nodes: m.nodes.map((n, i) => ({
          ip: n.ip,
          x: (l.x[i] - v.x) * v.k,
          y: (l.y[i] - v.y) * v.k,
          r: l.r[i] * v.k,
          tone: m.tones[i],
          visible: vis.nodes.has(n.ip),
          drawn: vis.nodes.has(n.ip) && circleInView(l.x[i], l.y[i], l.r[i] + 4, v, width, height),
        })),
        view: { ...v },
        settled: settled.current,
      }
    }
  }, [])

  const hovered = hover ? model.nodes[hover.index] : null
  const cursor = panning ? 'grabbing' : hover ? 'pointer' : 'grab'

  return (
    <div ref={box} className="relative w-full overflow-hidden rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900" data-testid="topology-box">
      <canvas
        ref={canvas}
        data-testid="topology-canvas"
        role="img"
        aria-label={`Network diagram of ${topology.nodes.length} addresses and ${topology.edges.length} connections. Use the search box to find an address.`}
        style={{ display: 'block', touchAction: 'none', cursor }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onPointerLeave={onPointerLeave}
      />
      {hovered && hover && (
        <div
          role="tooltip"
          data-testid="topology-tooltip"
          className="pointer-events-none absolute z-10 max-w-xs rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-theme-xs text-gray-700 dark:text-gray-200 shadow-theme-md"
          style={{ left: hover.left, top: hover.top }}
        >
          <div className="font-mono text-theme-sm font-semibold text-gray-800 dark:text-white/90">{hovered.ip}</div>
          <div>{hovered.type.replace('_', ' ')}</div>
          <div>
            {formatVolume(hovered.traffic_volume)} · {hovered.packets.toLocaleString()} packets
          </div>
          <div className={hovered.is_problematic ? 'font-medium text-error-600 dark:text-error-400' : ''}>
            {hovered.issue_count === 0 ? 'No issues' : `${hovered.issue_count.toLocaleString()} ${hovered.issue_count === 1 ? 'issue' : 'issues'}`}
          </div>
          {hovered.protocols.length > 0 && <div className="text-gray-500 dark:text-gray-400">{hovered.protocols.join(', ')}</div>}
        </div>
      )}
    </div>
  )
}
