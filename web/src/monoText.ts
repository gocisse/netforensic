/** A piece of text, and whether it is an address or a port that belongs in a monospace font. */
export interface Piece {
  text: string
  mono: boolean
}

const IPV4 = String.raw`\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?`
const HEX = '[0-9a-fA-F]{1,4}'
const IPV6_FULL = `(?:${HEX}:){7}${HEX}`
const IPV6_SHORT = `(?:${HEX}:){0,6}${HEX}?::(?:${HEX}:){0,6}${HEX}?`
const BRACKETED = String.raw`\[(?:[0-9a-fA-F:]+)\](?::\d{1,5})?`
const REVERSE = String.raw`(?:\d{1,3}\.){4}in-addr\.arpa(?:\.[\w-]+)*`
const PORT = String.raw`(?<=\bports? )\d{1,5}(?:, ?\d{1,5})*`

const PATTERN = new RegExp(`(?<![\\w:.])(?:${REVERSE}|${BRACKETED}|${IPV6_FULL}|${IPV6_SHORT}|${IPV4})(?![\\w:.]*\\w)|${PORT}`, 'g')

/**
 * Splits prose into pieces so that IP addresses (IPv4 or IPv6, with an
 * optional :port), reverse-lookup names and port numbers after the word "port" can be set in a
 * monospace font. Times such as 13:13:59.155 are not addresses and stay plain.
 */
export function splitMono(text: string): Piece[] {
  const out: Piece[] = []
  let last = 0
  for (const m of text.matchAll(PATTERN)) {
    const at = m.index ?? 0
    if (at > last) out.push({ text: text.slice(last, at), mono: false })
    out.push({ text: m[0], mono: true })
    last = at + m[0].length
  }
  if (last < text.length) out.push({ text: text.slice(last), mono: false })
  return out
}
