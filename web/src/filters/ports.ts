/** An inclusive range of ports. */
export interface PortRange {
  lo: number
  hi: number
}

const MAX_RANGES = 64

function parsePort(s: string): number | null {
  const t = s.trim()
  if (!/^\d+$/.test(t)) return null
  const n = Number(t)
  return n >= 1 && n <= 65535 ? n : null
}

/**
 * Reads a comma-separated list of ports and ranges, such as "80,443,8000-9000".
 * It returns the ranges, or an error message fit to show next to the field.
 * An empty string is no filter.
 */
export function parsePorts(text: string): { ranges: PortRange[] } | { error: string } {
  const s = text.trim()
  if (s === '') return { ranges: [] }
  const ranges: PortRange[] = []
  for (const raw of s.split(',')) {
    const part = raw.trim()
    if (part === '') return { error: 'Remove the empty entry between the commas.' }
    const dash = part.indexOf('-')
    const lo = parsePort(dash < 0 ? part : part.slice(0, dash))
    const hi = dash < 0 ? lo : parsePort(part.slice(dash + 1))
    if (lo === null || hi === null) return { error: `"${part}" is not a port from 1 to 65535 or a range like 8000-9000.` }
    if (hi < lo) return { error: `The range "${part}" runs backwards.` }
    ranges.push({ lo, hi })
    if (ranges.length > MAX_RANGES) return { error: `Use at most ${MAX_RANGES} ports or ranges.` }
  }
  return { ranges }
}

/** Whether port is in one of the ranges. */
export function portIn(ranges: PortRange[], port: number): boolean {
  return ranges.some((r) => port >= r.lo && port <= r.hi)
}
