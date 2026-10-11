import { formatBytes, formatMs, protocolColor } from '../format'
import type { Flow } from '../types'
import { Card, CardHeader } from './ui/Card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/Table'

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
                    <div className="truncate font-mono text-theme-xs" title={f.id}>
                      {f.id}
                    </div>
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
