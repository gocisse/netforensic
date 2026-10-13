/**
 * A force-directed layout: nodes push each other apart, edges pull the nodes
 * they join together, and a weak force toward the middle keeps separate parts
 * of the graph from drifting away. Pushing is only computed between nodes in
 * neighboring cells of a grid, so a tick costs about as much as the number of
 * nodes and edges, not the square of the nodes. The layout is deterministic:
 * nodes start on a spiral, the busiest in the middle.
 */

export interface LayoutEdge {
  a: number
  b: number
}

export class ForceLayout {
  readonly x: Float64Array
  readonly y: Float64Array
  readonly r: Float64Array
  private readonly vx: Float64Array
  private readonly vy: Float64Array
  private readonly edges: LayoutEdge[]
  private alpha = 1

  /** Cell size of the grid and the distance beyond which two nodes do not push each other. */
  private static readonly CELL = 140
  private static readonly ALPHA_MIN = 0.02
  private static readonly ALPHA_DECAY = 0.985

  /** `radii[i]` is the radius of node i; the nodes are expected busiest first. */
  constructor(radii: ArrayLike<number>, edges: LayoutEdge[]) {
    const n = radii.length
    this.x = new Float64Array(n)
    this.y = new Float64Array(n)
    this.r = Float64Array.from(radii)
    this.vx = new Float64Array(n)
    this.vy = new Float64Array(n)
    this.edges = edges
    const golden = Math.PI * (3 - Math.sqrt(5))
    for (let i = 0; i < n; i++) {
      const rad = 30 * Math.sqrt(i + 0.5)
      this.x[i] = rad * Math.cos(i * golden)
      this.y[i] = rad * Math.sin(i * golden)
    }
  }

  get done(): boolean {
    return this.alpha < ForceLayout.ALPHA_MIN
  }

  /** Moves the nodes one step and cools the layout down; returns whether it has settled. */
  tick(): boolean {
    const n = this.x.length
    if (n === 0) this.alpha = 0
    if (this.done) return true
    const { CELL } = ForceLayout
    const a = this.alpha

    // repulsion between nodes in neighboring cells
    const grid = new Map<number, number[]>()
    const cell = (v: number) => Math.floor(v / CELL)
    const key = (cx: number, cy: number) => cx * 73856093 ^ cy * 19349663
    for (let i = 0; i < n; i++) {
      const k = key(cell(this.x[i]), cell(this.y[i]))
      const list = grid.get(k)
      if (list) list.push(i)
      else grid.set(k, [i])
    }
    for (let i = 0; i < n; i++) {
      const cx = cell(this.x[i]), cy = cell(this.y[i])
      for (let gx = cx - 1; gx <= cx + 1; gx++) {
        for (let gy = cy - 1; gy <= cy + 1; gy++) {
          const list = grid.get(key(gx, gy))
          if (!list) continue
          for (const j of list) {
            if (j <= i) continue
            let dx = this.x[j] - this.x[i]
            let dy = this.y[j] - this.y[i]
            let d2 = dx * dx + dy * dy
            if (d2 === 0) {
              dx = (i % 2 ? 1 : -1) * 0.01
              dy = (j % 2 ? 1 : -1) * 0.01
              d2 = dx * dx + dy * dy
            }
            if (d2 > CELL * CELL) continue
            const d = Math.sqrt(d2)
            const minD = this.r[i] + this.r[j] + 14
            const force = ((minD * minD * 6) / d2 + 30 / d) * a
            const fx = (dx / d) * force
            const fy = (dy / d) * force
            this.vx[i] -= fx
            this.vy[i] -= fy
            this.vx[j] += fx
            this.vy[j] += fy
          }
        }
      }
    }
    // springs along the edges
    for (const e of this.edges) {
      const dx = this.x[e.b] - this.x[e.a]
      const dy = this.y[e.b] - this.y[e.a]
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01
      const rest = this.r[e.a] + this.r[e.b] + 60
      const f = ((d - rest) / d) * 0.3 * a
      this.vx[e.a] += dx * f
      this.vy[e.a] += dy * f
      this.vx[e.b] -= dx * f
      this.vy[e.b] -= dy * f
    }
    // a pull toward the middle, then move with friction
    for (let i = 0; i < n; i++) {
      this.vx[i] -= this.x[i] * 0.004 * a
      this.vy[i] -= this.y[i] * 0.004 * a
      const speed = Math.hypot(this.vx[i], this.vy[i])
      const cap = 60
      if (speed > cap) {
        this.vx[i] *= cap / speed
        this.vy[i] *= cap / speed
      }
      this.x[i] += this.vx[i]
      this.y[i] += this.vy[i]
      this.vx[i] *= 0.6
      this.vy[i] *= 0.6
    }
    this.alpha *= ForceLayout.ALPHA_DECAY
    return this.done
  }

  /** Runs ticks until the layout has settled or `max` ticks have run. */
  settle(max = 600): void {
    for (let i = 0; i < max && !this.tick(); i++);
  }
}
