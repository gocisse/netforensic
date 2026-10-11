import { formatBytes, formatMs, protocolColor } from '../format'
import type { Flow } from '../types'
import { Card, CardHeader } from './ui/Card'
import { ArrowBothIcon, ArrowLeftIcon, ArrowRightIcon } from '../icons'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/Table'

/** ip:port, with an IPv6 address in brackets and no port for portless protocols. */
function endpoint(ip: string, port: number): string {
  const host = ip.includes(':') ? `[${ip}]` : ip
  return port > 0 ? `${host}:${port}` : ip
}

/**
 * Which way most of a flow's bytes go. A flow is bidirectional and listed
 * with its lesser endpoint first, so the arrow shows the heavier direction:
 * → from the first endpoint to the second, ← the other way, ↔ if even.
 */
function direction(f: Flow): { Icon: typeof ArrowRightIcon; name: 'forward' | 'reverse' | 'even'; label: string } {
  const src = endpoint(f.src_ip, f.src_port)
  const dst = endpoint(f.dst_ip, f.dst_port)
  if (f.bytes_sent > f.bytes_recv) return { Icon: ArrowRightIcon, name: 'forward', label: `Most bytes go from ${src} to ${dst}` }
  if (f.bytes_recv > f.bytes_sent) return { Icon: ArrowLeftIcon, name: 'reverse', label: `Most bytes go from ${dst} to ${src}` }
  return { Icon: ArrowBothIcon, name: 'even', label: `Equal bytes in both directions between ${src} and ${dst}` }
}

/** The two endpoints of a flow with an arrow for the heavier direction; a reused-port or tunnel suffix of the ID follows. */
function FlowEndpoints({ flow }: { flow: Flow }) {
  const d = direction(flow)
  const suffix = /((?:#\d+)?(?:@.+)?)$/.exec(flow.id)?.[1] ?? ''
  return (
    <div className="flex items-center gap-1.5 font-mono text-theme-xs" title={flow.id} data-testid="flow-endpoints">
      <span className="truncate">{endpoint(flow.src_ip, flow.src_port)}</span>
      <span data-testid="flow-direction" data-direction={d.name} title={d.label} role="img" aria-label={d.label} className="flex-none text-brand-500">
        <d.Icon className="h-4 w-4" />
      </span>
      <span className="truncate">{endpoint(flow.dst_ip, flow.dst_port)}</span>
      {suffix && <span className="flex-none text-gray-400">{suffix}</span>}
    </div>
  )
}

interface Props {
  title: string
  flows: Flow[]
  emptyMessage: string
  testId: string
}

/** A table of flows with their protocol, volume and timing. */
export default function FlowTable({ title, flows, emptyMessage, testId }: Props) {
  return (
    <Card data-testid={testId}>
      <CardHeader title={title} />
      {flows.length === 0 ? (
        <p className="border-t border-gray-100 dark:border-gray-800 px-5 py-4 text-theme-sm text-gray-500 dark:text-gray-400 sm:px-6">{emptyMessage}</p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Flow</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead className="text-right">Packets</TableHead>
                <TableHead className="text-right">Bytes</TableHead>
                <TableHead className="text-right">Retrans.</TableHead>
                <TableHead className="text-right">Setup</TableHead>
                <TableHead className="text-right">TTFB</TableHead>
                <TableHead className="text-right">Avg RTT</TableHead>
                <TableHead className="text-right">Max RTT</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {flows.map((f) => (
                <TableRow key={f.id} data-testid="flow-row">
                  <TableCell className="max-w-xs text-gray-800 dark:text-white/90">
                    <FlowEndpoints flow={f} />
                    {f.app_protocol === 'DHCPv6' && (
                      <div className="truncate text-theme-xs text-gray-500 dark:text-gray-400" title={f.dhcpv6_client_id} data-testid="dhcpv6-details">
                        {f.dhcpv6_message_types}
                      </div>
                    )}
                    {f.app_protocol === 'QUIC' && (
                      <div className="truncate text-theme-xs text-gray-500 dark:text-gray-400" title={f.quic_packet_types} data-testid="quic-details">
                        {[f.quic_version, f.quic_packet_types].filter(Boolean).join(' · ')}
                      </div>
                    )}
                    {f.app_protocol === 'SIP' && (
                      <div className="truncate text-theme-xs text-gray-500 dark:text-gray-400" title={f.sip_call_id} data-testid="sip-details">
                        {[f.sip_method, f.sip_user_agent].filter(Boolean).join(' · ')}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    <span className={`rounded px-1.5 py-0.5 text-theme-xs font-medium ${protocolColor(f.protocol).badge}`}>{f.protocol || 'Other'}</span>
                    {f.app_protocol && (
                      <span className={`ml-1 rounded px-1.5 py-0.5 text-theme-xs font-medium ${protocolColor(f.app_protocol).badge}`}>{f.app_protocol}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{f.packet_count.toLocaleString()}</TableCell>
                  <TableCell className="whitespace-nowrap text-right tabular-nums">{formatBytes(f.bytes_sent + f.bytes_recv)}</TableCell>
                  <TableCell className="text-right tabular-nums">{f.retransmits || '–'}</TableCell>
                  <TableCell className="whitespace-nowrap text-right tabular-nums">{formatMs(f.setup_time_ms)}</TableCell>
                  <TableCell className="whitespace-nowrap text-right tabular-nums">{formatMs(f.ttfb_ms)}</TableCell>
                  <TableCell className="whitespace-nowrap text-right tabular-nums">{formatMs(f.avg_rtt_ms)}</TableCell>
                  <TableCell className="whitespace-nowrap text-right tabular-nums">{formatMs(f.max_rtt_ms)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </Card>
  )
}
