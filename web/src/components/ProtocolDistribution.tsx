import { PROTOCOL_FILTERS, protocolColor } from '../format'
import type { ProtocolStat } from '../types'
import { Card, CardBody, CardHeader } from './ui/Card'

interface Props {
  stats: ProtocolStat[]
  /** The protocol currently selected in the filter. */
  selected: string
  onSelect: (protocol: string) => void
}

function ProtocolPill({ stat, selected, onSelect }: { stat: ProtocolStat } & Pick<Props, 'selected' | 'onSelect'>) {
  const color = protocolColor(stat.protocol)
  const selectable = (PROTOCOL_FILTERS as readonly string[]).includes(stat.protocol)
  const active = selected === stat.protocol
  return (
    <button
      type="button"
      data-testid="protocol-badge"
      data-protocol={stat.protocol}
      disabled={!selectable}
      aria-pressed={selectable ? active : undefined}
      onClick={() => onSelect(active ? 'All' : stat.protocol)}
      title={selectable ? `Show only ${stat.protocol}` : undefined}
      className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-left text-theme-sm transition-colors ${
        active ? 'border-brand-500 bg-brand-25 dark:bg-brand-500/10 ring-1 ring-brand-500' : 'border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900'
      } ${selectable ? 'hover:bg-gray-50 dark:hover:bg-gray-800/60' : 'cursor-default'}`}
    >
      <span aria-hidden="true" className={`h-2.5 w-2.5 flex-none rounded-full ${color.dot}`} />
      <span className="font-semibold text-gray-800 dark:text-white/90">{stat.protocol}</span>
      <span className="text-gray-600 dark:text-gray-400">{stat.packets.toLocaleString()} pkts</span>
      <span className="text-gray-500 dark:text-gray-400">({stat.percent}%)</span>
      <span className="text-theme-xs text-gray-400">
        {stat.flows.toLocaleString()} {stat.flows === 1 ? 'flow' : 'flows'}
      </span>
    </button>
  )
}

/**
 * The traffic composition: a bar of the transport protocols, which add up to
 * all packets, and badges for every protocol, including the application
 * protocols recognized inside the flows.
 */
export default function ProtocolDistribution({ stats, selected, onSelect }: Props) {
  const transport = stats.filter((s) => s.layer === 'transport')
  const application = stats.filter((s) => s.layer === 'application')
  if (stats.length === 0) return null

  return (
    <Card data-testid="protocol-distribution">
      <CardHeader title="Protocol distribution" description="Select a protocol to filter the issues and flows below." />
      <CardBody>
        <div
          className="flex h-3 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800"
          role="img"
          aria-label={transport.map((s) => `${s.protocol} ${s.percent}%`).join(', ')}
        >
          {transport.map((s) => (
            <div
              key={s.protocol}
              className={protocolColor(s.protocol).bar}
              style={{ width: `${s.percent}%` }}
              title={`${s.protocol}: ${s.packets.toLocaleString()} packets (${s.percent}%)`}
            />
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {transport.map((s) => (
            <ProtocolPill key={s.protocol} stat={s} selected={selected} onSelect={onSelect} />
          ))}
        </div>
        {application.length > 0 && (
          <>
            <p className="mt-4 text-theme-xs text-gray-500 dark:text-gray-400">
              Recognized inside the flows above (every packet of such a flow counts, so these overlap the transport
              protocols; a flow without a captured handshake or header counts only as TCP or UDP):
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {application.map((s) => (
                <ProtocolPill key={s.protocol} stat={s} selected={selected} onSelect={onSelect} />
              ))}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  )
}
