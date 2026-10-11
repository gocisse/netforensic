import { ipKey } from './ip'

/** An address with an optional port (0 if there is none). */
export interface Endpoint {
  ip: string // as ipKey returns it
  port: number
}

function parseEndpoint(s: string): Endpoint | null {
  let host: string
  let port = ''
  if (s.startsWith('[')) {
    // [ip6] or [ip6]:port
    const end = s.indexOf(']')
    if (end < 0) return null
    host = s.slice(1, end)
    const rest = s.slice(end + 1)
    if (rest !== '') {
      if (!rest.startsWith(':')) return null
      port = rest.slice(1)
    }
  } else if (s.split(':').length === 2) {
    // ip4:port
    ;[host, port] = s.split(':')
  } else {
    // ip4, or a bare ip6
    host = s
  }
  const ip = ipKey(host)
  if (ip === null) return null
  if (port === '') return { ip, port: 0 }
  if (!/^\d+$/.test(port) || Number(port) > 65535) return null
  return { ip, port: Number(port) }
}

/**
 * Reads the addresses out of a reference to a flow ("ip:port-ip:port", with an
 * optional "#N" and "@tunnel" suffix) or to an endpoint ("ip:port",
 * "[ip6]:port" or just "ip"). It returns nothing for anything else, such as a
 * domain name or a Call-ID. The server's package filter does the same.
 */
export function parseRef(input: string | undefined): Endpoint[] {
  let ref = (input ?? '').trim()
  if (ref === '') return []
  const single = parseEndpoint(ref)
  if (single) return [single]
  const at = ref.indexOf('@')
  if (at >= 0) ref = ref.slice(0, at)
  const hash = ref.lastIndexOf('#')
  if (hash >= 0) ref = ref.slice(0, hash)
  for (let i = 0; i < ref.length; i++) {
    if (ref[i] !== '-') continue
    const a = parseEndpoint(ref.slice(0, i))
    const b = parseEndpoint(ref.slice(i + 1))
    if (a && b) return [a, b]
  }
  return []
}
