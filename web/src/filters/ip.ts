/**
 * IP address parsing for the filters. It accepts what Go's netip.ParseAddr
 * accepts on the server (so a filter means the same in the browser and in an
 * export): dotted-decimal IPv4 without leading zeros, and IPv6 with an
 * optional "::" and an optional embedded IPv4 tail, no zone.
 */

const OCTET = /^(0|[1-9]\d{0,2})$/
const GROUP = /^[0-9a-fA-F]{1,4}$/

function parseIPv4(s: string): number[] | null {
  const parts = s.split('.')
  if (parts.length !== 4) return null
  const out: number[] = []
  for (const p of parts) {
    if (!OCTET.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    out.push(n)
  }
  return out
}

function parseIPv6(s: string): number[] | null {
  if (s.includes('%') || !s.includes(':')) return null
  const dbl = s.indexOf('::')
  if (dbl >= 0 && s.indexOf('::', dbl + 1) >= 0) return null // at most one "::"

  const parseSide = (side: string): number[] | null => {
    if (side === '') return []
    const parts = side.split(':')
    const out: number[] = []
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i]
      if (i === parts.length - 1 && p.includes('.')) {
        const v4 = parseIPv4(p)
        if (!v4) return null
        out.push(v4[0] * 256 + v4[1], v4[2] * 256 + v4[3])
        continue
      }
      if (!GROUP.test(p)) return null
      out.push(parseInt(p, 16))
    }
    return out
  }

  if (dbl < 0) {
    const g = parseSide(s)
    return g && g.length === 8 ? g : null
  }
  const head = parseSide(s.slice(0, dbl))
  const tail = parseSide(s.slice(dbl + 2))
  if (!head || !tail) return null
  // an embedded IPv4 may only close the address, never end the head
  if (s.slice(0, dbl).includes('.')) return null
  const missing = 8 - head.length - tail.length
  if (missing < 1) return null // "::" stands for at least one group
  return [...head, ...new Array<number>(missing).fill(0), ...tail]
}

/**
 * Returns the form in which addresses are compared: IPv4 (and IPv4-mapped
 * IPv6) as dotted decimal, IPv6 as eight zero-padded lowercase groups. It
 * returns null if s is not an IP address.
 */
export function ipKey(s: string): string | null {
  const v4 = parseIPv4(s)
  if (v4) return v4.join('.')
  const v6 = parseIPv6(s)
  if (!v6) return null
  if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
    return [v6[6] >> 8, v6[6] & 0xff, v6[7] >> 8, v6[7] & 0xff].join('.')
  }
  return v6.map((g) => g.toString(16).padStart(4, '0')).join(':')
}

/** Whether s is an IPv4 or IPv6 address. */
export function isIP(s: string): boolean {
  return ipKey(s) !== null
}

/**
 * Writes an address as a person would: IPv6 with leading zeros dropped and the
 * longest run of zero groups as "::". It takes the form ipKey returns, and
 * returns anything else unchanged.
 */
export function displayIP(key: string): string {
  const groups = key.split(':')
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{4}$/.test(g))) return key
  const g = groups.map((x) => x.replace(/^0+(?=.)/, ''))
  let bestStart = -1
  let bestLen = 0
  for (let i = 0; i < 8; ) {
    if (g[i] !== '0') {
      i++
      continue
    }
    let j = i
    while (j < 8 && g[j] === '0') j++
    if (j - i > bestLen) {
      bestStart = i
      bestLen = j - i
    }
    i = j
  }
  if (bestLen < 2) return g.join(':')
  const head = g.slice(0, bestStart).join(':')
  const tail = g.slice(bestStart + bestLen).join(':')
  return `${head}::${tail}`
}
