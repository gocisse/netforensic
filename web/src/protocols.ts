import type { Issue } from './types'

/** A protocol with its own page. */
export interface ProtocolPageInfo {
  /** The path segment: /analysis/:id/<slug>. */
  slug: string
  /** The protocol as issues name it in `protocols`. */
  protocol: string
  title: string
  /** What the page is about, and what its issues mean. */
  blurb: string
}

/** The protocol pages, in the order of the navigation bar. */
export const PROTOCOL_PAGES: ProtocolPageInfo[] = [
  {
    slug: 'tcp',
    protocol: 'TCP',
    title: 'TCP issues',
    blurb: 'Retransmissions and packet loss, resets, zero windows, handshake problems and slow connections, including those of the protocols that run over TCP (HTTP, TLS).',
  },
  { slug: 'udp', protocol: 'UDP', title: 'UDP issues', blurb: 'Issues in UDP traffic, including the protocols that run over it (DNS, SIP, DHCPv6, QUIC). UDP itself has no retransmissions or handshakes, so problems show up in those protocols.' },
  { slug: 'dns', protocol: 'DNS', title: 'DNS issues', blurb: 'Failed lookups (NXDOMAIN, SERVFAIL), queries that got no answer and slow resolvers.' },
  { slug: 'http', protocol: 'HTTP', title: 'HTTP issues', blurb: 'Error responses (4xx and 5xx) and slow responses in unencrypted HTTP.' },
  { slug: 'tls', protocol: 'TLS', title: 'TLS issues', blurb: 'Handshake failures and protocol downgrades, as far as they are visible without decrypting the traffic.' },
  { slug: 'sip', protocol: 'SIP', title: 'SIP issues', blurb: 'VoIP problems: registrations that fail, calls that cannot be set up and high error rates.' },
  { slug: 'dhcpv6', protocol: 'DHCPv6', title: 'DHCPv6 issues', blurb: 'IPv6 address and prefix assignment problems: no addresses available, configuration errors and requests nobody answered.' },
  { slug: 'quic', protocol: 'QUIC', title: 'QUIC issues', blurb: 'Handshake timeouts, Retry, Version Negotiation and draft versions. QUIC is encrypted, so only its handshake can be judged.' },
]

/** Whether an issue involves a protocol, as the protocol filter judges it. */
export function involvesProtocol(issue: Issue, protocol: string): boolean {
  return (issue.protocols ?? []).some((p) => p.toLowerCase() === protocol.toLowerCase())
}

/** The page of a protocol, by its path segment. */
export function pageInfo(slug: string): ProtocolPageInfo {
  const info = PROTOCOL_PAGES.find((p) => p.slug === slug)
  if (!info) throw new Error(`no protocol page ${slug}`)
  return info
}
