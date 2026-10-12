import { parseRef } from './filters/refs.ts'
import type { Endpoint } from './filters/refs.ts'
import type { Issue } from './types.ts'

/** Quotes a string for a POSIX shell: in single quotes, with each ' written as '\''. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

/**
 * The command that opens a capture in Wireshark with the filter applied, or
 * runs it in tshark. Wireshark registers no link scheme that opens a capture
 * with a filter, so a command to copy is the nearest thing.
 */
export function wiresharkCommand(captureName: string, filter: string): string {
  return `wireshark -r ${shellQuote(captureName)} -Y ${shellQuote(filter)}`
}

/** The tshark command that lists the packets a filter matches; with `head`, only the first that many. */
export function tsharkCommand(captureName: string, filter: string, head?: number): string {
  const cmd = `tshark -r ${shellQuote(captureName)} -Y ${shellQuote(filter)}`
  return head && head > 0 ? `${cmd} | head -${Math.floor(head)}` : cmd
}

/**
 * Encodes a filter for use in a URL query (for example in a link that carries
 * it). Display filters hold &, #, +, %, quotes and spaces, all of which would
 * otherwise end or alter the value.
 */
export function filterForUrl(filter: string): string {
  return encodeURIComponent(filter)
}

/** What an issue is about, as the page lists it: a flow or a name, and the endpoints of a flow. */
export interface Affected {
  /** The text shown. */
  label: string
  /** The two endpoints if it is a flow, one if it is an address, none for a name. */
  endpoints: Endpoint[]
}

/**
 * The flows, addresses and names an issue is about: its flow, its target and
 * the subjects of its events, each once. Names that are not addresses (a
 * domain, a Call-ID) are listed too, without endpoints.
 */
export function affectedOf(issue: Issue): Affected[] {
  const seen = new Set<string>()
  const out: Affected[] = []
  const add = (label: string | undefined) => {
    if (!label || seen.has(label)) return
    seen.add(label)
    out.push({ label, endpoints: parseRef(label) })
  }
  add(issue.flow_id)
  add(issue.target)
  for (const o of issue.occurrences ?? []) add(o.subject)
  return out
}
