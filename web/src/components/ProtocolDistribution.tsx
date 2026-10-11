import { PROTOCOL_FILTERS, protocolColor } from '../format'
import type { ProtocolStat } from '../types'

interface Props {
  stats: ProtocolStat[]
  /** The protocol currently selected in the filter. */
  selected: string
  onSelect: (protocol: string) => void
}

function Badge({ stat, selected, onSelect }: { stat: ProtocolStat } & Pick<Props, 'selected' | 'onSelect'>) {
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
      className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-left text-sm transition-colors ${
        active ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-200'
      } ${selectable ? 'hover:bg-slate-50' : 'cursor-default'}`}
    >
      <span aria-hidden="true" className={`h-2.5 w-2.5 flex-none rounded-full ${color.dot}`} />
      <span className="font-semibold text-slate-900">{stat.protocol}</span>
      <span className="text-slate-600">{stat.packets.toLocaleString()} pkts</span>
      <span className="text-slate-500">({stat.percent}%)</span>
      <span className="text-xs text-slate-400">
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
    <section data-testid="protocol-distribution" aria-label="Protocol distribution">
      <h3 className="mb-2 text-sm font-semibold text-slate-900">Protocol distribution</h3>
      <div
        className="flex h-3 w-full overflow-hidden rounded-full bg-slate-100"
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
      <div className="mt-3 flex flex-wrap gap-2">
        {transport.map((s) => (
          <Badge key={s.protocol} stat={s} selected={selected} onSelect={onSelect} />
        ))}
      </div>
      {application.length > 0 && (
        <>
          <p className="mt-3 text-xs text-slate-500">
            Recognized inside the flows above (every packet of such a flow counts, so these overlap the transport
            protocols; a flow without a captured handshake or header counts only as TCP or UDP):
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            {application.map((s) => (
              <Badge key={s.protocol} stat={s} selected={selected} onSelect={onSelect} />
            ))}
          </div>
        </>
      )}
    </section>
  )
}
