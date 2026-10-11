import type { Flow, Issue, ProtocolStat, Severity } from './types'

/*
 * Plain-language versions of what the analysis says, for the Junior
 * dashboard: what an issue means in everyday words and what to try, without
 * protocol names, packet counts or Wireshark. The Senior dashboard shows the
 * technical text instead.
 */

/** An issue in plain words. */
export interface PlainIssue {
  /** A short title without jargon. */
  title: string
  /** What it means, in one or two sentences. */
  meaning: string
  /** What to try, as short steps. */
  steps: string[]
}

const ASK = 'Ask your network team, and tell them the time this happened.'

const ISSUES: Record<string, PlainIssue> = {
  'Fast Retransmit': {
    title: 'A little data got lost',
    meaning: 'A few pieces of data went missing on the way and were sent again straight away. You probably did not notice anything.',
    steps: ['If it only happens now and then, no action is needed.', 'If it happens a lot, check the network cable or Wi-Fi signal of the affected computer.', ASK],
  },
  'Timeout Retransmit': {
    title: 'Data was lost and things stalled',
    meaning: 'Some data had to be resent because it got lost on the network, and the connection stalled while it waited. This usually means the network is overloaded or a cable or device is failing.',
    steps: ['Check that network cables are plugged in firmly and Wi-Fi is strong.', 'Find out whether someone is downloading or uploading something very large.', 'Restart the affected device, then ask your network team to look at the link.'],
  },
  'TCP Retransmissions detected': {
    title: 'Some data had to be sent again',
    meaning: 'Some information did not arrive the first time and had to be resent. That slows things down.',
    steps: ['Check the cable or Wi-Fi of the affected computer.', 'Ask whether the network is busy at this time.', ASK],
  },
  'TCP Zero Window': {
    title: 'A computer could not keep up',
    meaning: 'One computer told the other to stop sending because it was too busy to take in more. The problem is on that computer, not on the network.',
    steps: ['Find out which computer was receiving the data.', 'Close programs that are using a lot of its memory or processor, or restart it.', 'If it keeps happening, ask the owner of that application to look at it.'],
  },
  'Connection reset after zero-window stall': {
    title: 'A busy computer dropped a connection',
    meaning: 'One computer got overloaded, stopped accepting data, and the connection was then cut. The cause is most likely the overloaded computer or its application.',
    steps: ['Find out which computer was receiving the data and restart the program it was running.', 'Check whether that computer was short of memory or very busy.', 'If it repeats, ask the owner of the application.'],
  },
  'Connection Refused (Port Closed)': {
    title: 'A service is not available',
    meaning: 'Computers tried to use a service, and the computer that should offer it said no. Either the service is not running or something blocks it.',
    steps: ['Check that the service or program is switched on.', 'Check that the program is pointed at the right server.', 'Ask your network team whether a firewall blocks it.'],
  },
  'Connection Abruptly Closed': {
    title: 'A connection was cut off',
    meaning: 'A connection that was working was ended suddenly instead of being closed politely. Whatever was being done may have failed halfway.',
    steps: ['Try the action again and see whether it works.', 'If it keeps happening, restart the program or device that was using the connection.', ASK],
  },
  'Connection Idle Timeout': {
    title: 'A quiet connection was closed',
    meaning: 'A connection that had been quiet for a while was closed, probably by a firewall or a server that cleans up unused connections. This is usually harmless.',
    steps: ['If a program lost its connection after being idle, just reconnect.', 'If it happens often, ask your network team to raise the idle time limit.'],
  },
  'Stray RST / Port Probe': {
    title: 'Unexpected "go away" replies',
    meaning: 'Some computers answered messages that did not belong to any connection we saw. This can happen when a recording starts late, or when something is scanning the network.',
    steps: ['If the recording started in the middle of activity, you can ignore this.', 'If you do not expect network scans, tell your security team.'],
  },
  'Unanswered SYN': {
    title: 'Requests got no answer',
    meaning: 'Computers asked to connect, and no reply was seen. The server may be off, blocked by a firewall, or the replies took a path this recording did not see.',
    steps: ['Check that the server or service is switched on.', 'Ask your network team whether a firewall drops these requests.', 'If the recording only sees one side of the traffic, record again closer to the server.'],
  },
  'Possible SYN Flood': {
    title: 'Possible flood of connection requests',
    meaning: 'A very large number of connection requests went to one service in a short time and were not answered. This can be an attack, or a service that cannot keep up.',
    steps: ['Check whether the service is overloaded or down.', 'Tell your security team right away if you did not expect this much traffic.', 'Do not restart the service before they have had a look, if an attack is possible.'],
  },
  'SYN Retried Before Answer': {
    title: 'Connections started slowly',
    meaning: 'The first request to connect got no answer and the computer had to ask again. Connections still worked, but they started late.',
    steps: ['If things feel slow to start, check the network cable or Wi-Fi.', ASK],
  },
  'Slow TCP Handshake': {
    title: 'Connections take a long time to start',
    meaning: 'Setting up a connection took longer than it should. Programs feel slow to start working, even if the rest is fine.',
    steps: ['Check whether the network is busy.', 'Check the Wi-Fi signal or cable of the affected computer.', 'Ask your network team how far away the server is.'],
  },
  'Slow Server Response': {
    title: 'A server is slow to answer',
    meaning: 'The connection was set up quickly, but the server then took a long time to reply. The server or the program behind it is busy.',
    steps: ['Try again later; the server may be overloaded for a moment.', 'Tell the owner of the application or server that it is slow.'],
  },
  'High Network Latency': {
    title: 'The network is slow to respond',
    meaning: 'Messages take a long time to get there and back, so everything feels sluggish. The network may be crowded or the other side is very far away.',
    steps: ['Find out whether someone is using a lot of bandwidth.', 'Try a wired connection instead of Wi-Fi.', 'Ask your network team to check the link.'],
  },
  'High Jitter': {
    title: 'The network speed jumps around',
    meaning: 'Response times swing from fast to very slow. Calls and video suffer most, because they need an even flow of data.',
    steps: ['Avoid large downloads during calls.', 'Try a wired connection instead of Wi-Fi.', 'Ask your network team to check for crowded links.'],
  },
  'DNS NXDOMAIN': {
    title: 'Some names do not exist',
    meaning: 'Computers asked for the address of names that the name service says do not exist. A name may be misspelled, old, or removed.',
    steps: ['Check the spelling of the website or server name.', 'If a program uses an old server name, update its settings.', 'If it happens a lot, ask your network team to look at the name service.'],
  },
  'DNS SERVFAIL': {
    title: 'The name service had a problem',
    meaning: 'The service that turns names into addresses could not answer. Websites and apps may fail to connect.',
    steps: ['Try again in a few minutes.', 'Try another name service if your network offers one.', 'Tell your network team that name lookups are failing.'],
  },
  'DNS Timeout': {
    title: 'The name service did not answer',
    meaning: 'Computers asked for the address behind a name and got no reply at all. Websites and apps may hang or fail.',
    steps: ['Check that the computer is connected to the network.', 'Ask your network team whether the name service is running.', 'Try a different name service if you can.'],
  },
  'DNS Slow Response': {
    title: 'The name service is slow',
    meaning: 'Looking up names takes longer than it should, which makes websites and apps slow to start.',
    steps: ['Try again later; it may be busy for a moment.', 'Ask your network team to check the name service.'],
  },
  'HTTP Client Error': {
    title: 'A website refused a request',
    meaning: 'A web server said the request was wrong or not allowed, for example a page that does not exist or a login that is needed.',
    steps: ['Check the web address.', 'Check that you are signed in and allowed to see the page.', 'If a program makes the request, check its settings.'],
  },
  'HTTP Server Error': {
    title: 'A website had a problem',
    meaning: 'A web server broke while handling a request. The problem is on the server, not on your computer.',
    steps: ['Try again in a few minutes.', 'Tell the owner of the website or application.'],
  },
  'HTTP Slow Response': {
    title: 'A website was slow to answer',
    meaning: 'A web server took more than a second to reply. The server or the program behind it is busy.',
    steps: ['Try again later.', 'Tell the owner of the website if it keeps being slow.'],
  },
  'TLS Handshake Failure': {
    title: 'A secure connection could not be set up',
    meaning: 'Two computers could not agree on how to talk securely, or one of them did not trust the other. The secure website or app does not work.',
    steps: ['Check that the date and time on the computer are correct.', 'Check that the program is up to date.', 'Ask your network team whether the website certificate is valid.'],
  },
  'TLS Protocol Downgrade': {
    title: 'An old, weaker security setting was used',
    meaning: 'A secure connection was set up with an older and weaker standard than the computer offered. It still works, but it is less safe.',
    steps: ['Tell the owner of the server to update its security settings.', 'If you did not expect this, tell your security team.'],
  },
  'ICMP Destination Unreachable': {
    title: 'Some places could not be reached',
    meaning: 'Network devices reported that some computers or services could not be reached. Whoever tried to reach them got an error.',
    steps: ['Check that the computer or service you want is switched on and connected.', 'Check the address you are using.', 'Ask your network team about routes or firewall rules.'],
  },
  'ICMP Time Exceeded': {
    title: 'Messages got lost in transit',
    meaning: 'Some messages used up their travel time before reaching their destination. A few of these are normal; many can mean a loop in the network.',
    steps: ['If you only see a few, you can ignore them.', 'If you see many, ask your network team to check for a network loop.'],
  },
  'ICMP Redirect': {
    title: 'A device suggested a different route',
    meaning: 'A network device told a computer to use another route for some traffic. Usually harmless, but it can also be used to divert traffic.',
    steps: ['Ask your network team whether the routing setup is as intended.', 'If you did not expect this, tell your security team.'],
  },
  'ARP Storm': {
    title: 'A flood of "who is there?" messages',
    meaning: 'Computers sent an unusually large number of messages asking who owns an address. This can slow the network down, and is often caused by a network loop or a misbehaving device.',
    steps: ['Find out whether a device was just plugged in or restarted.', 'Disconnect the device that sends the most, if you can tell which one it is.', 'Ask your network team to check for loops.'],
  },
  'Duplicate IP Address': {
    title: 'Two devices use the same address',
    meaning: 'Two devices claim the same network address, so traffic goes to the wrong one at times. Connections will keep dropping.',
    steps: ['Find the two devices (their hardware addresses are in the technical view).', 'Give one of them a different address.', 'Ask your network team to fix the address list.'],
  },
  'SIP Registration Failed': {
    title: 'A phone could not sign in',
    meaning: 'An office phone or phone app could not register with the phone system, so it cannot make or receive calls.',
    steps: ['Check the username and password of the phone.', 'Check that the phone is connected to the network.', 'Ask the phone-system administrator whether the account is active.'],
  },
  'SIP Call Setup Failed': {
    title: 'Phone calls could not be connected',
    meaning: 'Some calls were refused or could not be put through. The person may be busy, the number wrong, or the phone system may be overloaded.',
    steps: ['Check the number that was dialled.', 'Try the call again a bit later.', 'If many calls fail, tell the phone-system administrator.'],
  },
  'High SIP Error Rate': {
    title: 'Many phone requests are failing',
    meaning: 'More than one in ten requests to the phone system failed. Calls may drop or never connect.',
    steps: ['Tell the phone-system administrator.', 'Check whether the phone system or the internet line is overloaded.'],
  },
  'DHCPv6 No Addresses Available': {
    title: 'No network addresses left to hand out',
    meaning: 'Devices asked the network for an address and the server had none to give. Those devices cannot connect properly.',
    steps: ['Ask your network team to enlarge the pool of addresses.', 'Remove old or unused devices from the list.', 'Restart the affected device once there are addresses again.'],
  },
  'DHCPv6 Configuration Error': {
    title: 'A device got a wrong network setting',
    meaning: 'The network server turned down a request because it does not fit how the network is set up. The device may end up without a working address.',
    steps: ['Make sure the device is plugged into the right network.', 'Restart the device.', 'Ask your network team to check the address settings.'],
  },
  'High DHCPv6 Failure Rate': {
    title: 'Many address requests are failing',
    meaning: 'The server that hands out network addresses is turning down a lot of requests, so many devices have trouble joining the network.',
    steps: ['Tell your network team.', 'Check that the address server is healthy and has addresses left.'],
  },
  'DHCPv6 Timeout': {
    title: 'The address server did not answer',
    meaning: 'Devices asked for a network address and nobody replied. They may be left without a working connection.',
    steps: ['Check that the device is connected to the right network.', 'Ask your network team whether the address server is running.', 'Restart the device afterwards.'],
  },
  'QUIC Handshake Timeout': {
    title: 'A modern web connection did not start',
    meaning: 'A browser tried to use a newer, faster kind of web connection and got no reply, often because a firewall blocks it. Browsers usually fall back to the older kind, so you may not notice.',
    steps: ['If websites load fine, you can ignore this.', 'If some sites are slow to start, ask your network team whether they block this type of traffic.'],
  },
  'QUIC Retry': {
    title: 'A server asked for an extra check',
    meaning: 'A server made the browser prove where it is coming from before continuing. This costs a tiny delay and is normal.',
    steps: ['No action is needed.'],
  },
  'QUIC Version Negotiation': {
    title: 'Browser and server picked a common version',
    meaning: 'The browser and the server first had to agree on which version of a connection type to use. This is normal.',
    steps: ['No action is needed if the website works.'],
  },
  'QUIC Draft Version': {
    title: 'An out-of-date browser or app',
    meaning: 'A program is using an early test version of a connection standard that servers may stop accepting.',
    steps: ['Update the browser or app to its latest version.'],
  },
}

const BY_CATEGORY: Record<string, PlainIssue> = {
  PacketLoss: { title: 'Some data was lost', meaning: 'Some information did not arrive and had to be sent again, which slows things down.', steps: ['Check the cable or Wi-Fi.', ASK] },
  Connection: { title: 'A connection problem', meaning: 'Some connections could not be made or were cut off.', steps: ['Try the action again.', ASK] },
  Performance: { title: 'Things are slow', meaning: 'Some connections are slower than they should be.', steps: ['Check whether the network is busy.', ASK] },
  DNS: { title: 'A name lookup problem', meaning: 'Looking up names did not work as it should.', steps: ['Try again in a few minutes.', ASK] },
  HTTP: { title: 'A website problem', meaning: 'A website did not answer the way it should.', steps: ['Try again later.', 'Tell the owner of the website.'] },
  TLS: { title: 'A secure connection problem', meaning: 'A secure connection could not be set up properly.', steps: ['Check the date and time on the computer.', ASK] },
  ICMP: { title: 'A delivery problem', meaning: 'Network devices reported trouble delivering messages.', steps: [ASK] },
  ARP: { title: 'A local network problem', meaning: 'Devices on the local network are not behaving as expected.', steps: [ASK] },
  SIP: { title: 'A phone problem', meaning: 'Phone calls or phone sign-ins are failing.', steps: ['Tell the phone-system administrator.'] },
  DHCPv6: { title: 'A network address problem', meaning: 'Devices have trouble getting a network address.', steps: [ASK] },
  QUIC: { title: 'A modern web connection note', meaning: 'Something about the newer kind of web connection is worth knowing.', steps: ['No action is needed if websites work.'] },
}

const GENERIC: PlainIssue = { title: 'Something needs a look', meaning: 'The analysis found something unusual that may affect how well the network works.', steps: [ASK] }

/** The plain-language version of an issue. */
export function plainIssue(issue: Pick<Issue, 'title' | 'category'>): PlainIssue {
  const exact = ISSUES[issue.title]
  if (exact) return exact
  const prefix = Object.keys(ISSUES).find((k) => issue.title.startsWith(k))
  if (prefix) return ISSUES[prefix]
  return BY_CATEGORY[issue.category] ?? GENERIC
}

/** The three lights of the health score. */
export type Light = 'green' | 'yellow' | 'red'

/** The traffic light and the words for a health score: green from 80, yellow from 40, red below that. */
export function healthLight(score: number): { light: Light; headline: string; detail: string } {
  if (score >= 80) return { light: 'green', headline: 'Network is healthy', detail: 'Nothing here needs your attention right now.' }
  if (score >= 40) return { light: 'yellow', headline: 'Network has some problems', detail: 'Things work, but some people may notice slowness or interruptions.' }
  return { light: 'red', headline: 'Network has serious issues', detail: 'Parts of the network are not working properly and need attention soon.' }
}

/**
 * The main cause of the problems, in plain words. The analysis names it in
 * technical terms ("Network congestion", or the title of the worst issue).
 */
export function plainRootCause(cause: string): { title: string; text: string } {
  const fixed: Record<string, { title: string; text: string }> = {
    'No significant issues detected': { title: 'Everything looks fine', text: 'The recording shows no real problems.' },
    'Network congestion': { title: 'The network is too busy', text: 'The network is overloaded: replies are slow and some data had to be sent again. Try to find out what is using so much capacity.' },
    'Packet loss': { title: 'Data is getting lost', text: 'Some data had to be resent because it got lost on the network. This usually means the network is overloaded or a cable/device is failing.' },
    'Fast Retransmit (isolated packet loss)': { title: 'A little data got lost', text: 'A few pieces of data got lost and were repaired straight away. This is usually nothing to worry about, unless it happens a lot.' },
    'Timeout Retransmit (severe congestion or blackhole)': { title: 'Data was lost and things stalled', text: 'Some data had to be resent because it got lost on the network. This usually means the network is overloaded or a cable/device is failing.' },
  }
  const hit = fixed[cause]
  if (hit) return hit
  if (cause.startsWith('DNS resolution failure')) {
    return { title: 'Name lookups are failing', text: 'Computers could not look up the addresses behind some names. Without that, websites and apps cannot connect.' }
  }
  if (cause.startsWith('Service Unavailable / Port Closed')) {
    return { title: 'A service is not available', text: 'Computers tried to use a service that is not running or is blocked, and were turned away.' }
  }
  const p = plainIssue({ title: cause, category: '' })
  return p === GENERIC ? { title: 'Something needs a look', text: 'The analysis found a problem, but it has no simple description. Switch to Senior mode for the technical details.' } : { title: p.title, text: p.meaning }
}

/** The look of a severity in the Junior view: an icon kind and a label. */
export function plainSeverity(s: Severity): { label: string; kind: 'error' | 'warning' | 'info' } {
  if (s === 'ERROR' || s === 'CRITICAL') return { label: 'Serious', kind: 'error' }
  if (s === 'WARNING') return { label: 'Needs attention', kind: 'warning' }
  return { label: 'Good to know', kind: 'info' }
}

/** What kind of traffic a group of protocols is, for the Junior protocol bars. */
export interface ProtocolGroup {
  key: string
  label: string
  /** Application protocols that belong to the group. */
  apps: string[]
  /** Transport protocols that count whole towards the group. */
  transports: string[]
  /** Tailwind classes for the bar. */
  bar: string
}

/** Groups of protocols, in the order they are listed. "Other" takes what no group claims. */
export const PROTOCOL_GROUPS: ProtocolGroup[] = [
  { key: 'web', label: 'Web traffic (HTTP/HTTPS)', apps: ['HTTP', 'TLS'], transports: [], bar: 'bg-brand-500' },
  { key: 'names', label: 'Name lookups (DNS)', apps: ['DNS'], transports: [], bar: 'bg-violet-500' },
  { key: 'voice', label: 'Voice and video (SIP/QUIC)', apps: ['SIP', 'QUIC'], transports: [], bar: 'bg-pink-500' },
  { key: 'setup', label: 'Network setup (addresses)', apps: ['DHCPv6'], transports: [], bar: 'bg-teal-500' },
  { key: 'housekeeping', label: 'Network housekeeping (ARP/ICMP)', apps: [], transports: ['ARP', 'ICMP'], bar: 'bg-warning-500' },
]

/** One bar of the Junior protocol view. */
export interface GroupShare {
  key: string
  label: string
  percent: number
  bar: string
}

/**
 * Sums the protocol statistics into the groups: an application protocol's
 * packets belong to its group, ARP and ICMP packets to housekeeping, and the
 * rest of the transport traffic is "Other data". Empty groups are left out.
 */
export function groupProtocols(stats: ProtocolStat[]): GroupShare[] {
  const transport = stats.filter((s) => s.layer === 'transport')
  const total = transport.reduce((n, s) => n + s.packets, 0)
  if (total === 0) return []
  const sums = new Map<string, number>()
  let claimed = 0
  for (const g of PROTOCOL_GROUPS) {
    let n = 0
    for (const s of stats) {
      if (s.layer === 'application' && g.apps.includes(s.protocol)) n += s.packets
      if (s.layer === 'transport' && g.transports.includes(s.protocol)) n += s.packets
    }
    sums.set(g.key, n)
    claimed += n
  }
  const rest = Math.max(0, total - claimed)
  const shares: GroupShare[] = PROTOCOL_GROUPS.map((g) => ({ key: g.key, label: g.label, percent: ((sums.get(g.key) ?? 0) * 100) / total, bar: g.bar }))
  shares.push({ key: 'other', label: 'Other data', percent: (rest * 100) / total, bar: 'bg-gray-400' })
  return shares.filter((s) => s.percent > 0).map((s) => ({ ...s, percent: Math.round(s.percent * 10) / 10 }))
}

const SERVICES: Record<number, string> = {
  20: 'File transfer', 21: 'File transfer', 22: 'Remote login', 23: 'Remote login', 25: 'Email', 53: 'Name lookup', 67: 'Network setup', 68: 'Network setup',
  80: 'Web', 110: 'Email', 123: 'Time sync', 143: 'Email', 161: 'Device monitoring', 389: 'Directory login', 443: 'Secure web', 445: 'File sharing',
  465: 'Email', 514: 'Logging', 587: 'Email', 636: 'Directory login', 993: 'Email', 995: 'Email', 1433: 'Database', 3306: 'Database', 3389: 'Remote desktop',
  5060: 'Phone call', 5061: 'Phone call', 5432: 'Database', 8080: 'Web', 8443: 'Secure web',
}

/** A flow in plain words: who talks to whom, about what. */
export interface PlainFlow {
  from: string
  to: string
  what: string
  status: 'working' | 'slow' | 'broken'
}

function host(ip: string): string {
  return ip
}

/**
 * Reads a flow for the Junior table. A flow lists its lesser endpoint first;
 * the one with the lower port, if the ports differ, is taken for the server
 * (clients use high ports) and the other for the client.
 */
export function plainFlow(f: Flow): PlainFlow {
  const swap = f.src_port !== f.dst_port && f.src_port !== 0 && f.dst_port !== 0 && f.src_port < f.dst_port
  const [cli, srv, sport] = swap ? [f.dst_ip, f.src_ip, f.src_port] : [f.src_ip, f.dst_ip, f.dst_port]
  const app = f.app_protocol
  let what = SERVICES[sport] ?? ''
  if (app === 'DNS') what = 'Name lookup'
  else if (app === 'SIP') what = 'Phone call'
  else if (app === 'QUIC') what = 'Modern web connection'
  else if (app === 'DHCPv6') what = 'Network setup'
  else if (app === 'HTTP') what = 'Web'
  else if (app === 'TLS' && what === '') what = 'Secure connection'
  if (what === '') what = f.protocol === 'ICMP' ? 'Network messages' : f.protocol === 'ARP' ? 'Local address lookup' : 'Other data'
  const status = f.status === 'broken' || f.status === 'slow' ? f.status : 'working'
  return { from: host(cli), to: host(srv), what, status }
}

/** The words of a flow status. */
export const FLOW_STATUS_LABEL: Record<PlainFlow['status'], string> = { working: 'Working', slow: 'Slow', broken: 'Broken' }
