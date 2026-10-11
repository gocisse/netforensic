import { formatBytes, formatMs, protocolColor } from '../format'
import type { Flow } from '../types'

interface Props {
  title: string
  flows: Flow[]
  emptyMessage: string
  testId: string
}

/** A compact table of flows with their protocol, volume and timing. */
export default function FlowTable({ title, flows, emptyMessage, testId }: Props) {
  return (
    <div data-testid={testId}>
      <h3 className="mb-2 text-sm font-semibold text-slate-900">{title}</h3>
      {flows.length === 0 ? (
        <p className="text-sm text-slate-500">{emptyMessage}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-3 py-2 font-semibold">Flow</th>
                <th className="px-3 py-2 font-semibold">Protocol</th>
                <th className="px-3 py-2 text-right font-semibold">Packets</th>
                <th className="px-3 py-2 text-right font-semibold">Bytes</th>
                <th className="px-3 py-2 text-right font-semibold">Retrans.</th>
                <th className="px-3 py-2 text-right font-semibold">Setup</th>
                <th className="px-3 py-2 text-right font-semibold">TTFB</th>
                <th className="px-3 py-2 text-right font-semibold">Avg RTT</th>
                <th className="px-3 py-2 text-right font-semibold">Max RTT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {flows.map((f) => (
                <tr key={f.id} data-testid="flow-row">
                  <td className="max-w-xs truncate px-3 py-2 font-mono text-xs text-slate-900" title={f.id}>
                    {f.id}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2">
                    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${protocolColor(f.protocol).badge}`}>
                      {f.protocol || 'Other'}
                    </span>
                    {f.app_protocol && (
                      <span className={`ml-1 rounded px-1.5 py-0.5 text-xs font-medium ${protocolColor(f.app_protocol).badge}`}>
                        {f.app_protocol}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{f.packet_count.toLocaleString()}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums">
                    {formatBytes(f.bytes_sent + f.bytes_recv)}
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{f.retransmits || '–'}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums">{formatMs(f.setup_time_ms)}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums">{formatMs(f.ttfb_ms)}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums">{formatMs(f.avg_rtt_ms)}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-right tabular-nums">{formatMs(f.max_rtt_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
