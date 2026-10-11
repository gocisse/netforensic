import { formatBytes } from '../format'
import type { Talker } from '../filters/match'
import { Card, CardHeader } from './ui/Card'

interface Props {
  talkers: Talker[]
  /** The IP address the source-IP filter is set to, if any. */
  selected: string
  onSelect: (ip: string) => void
}

/**
 * The busiest addresses by bytes. Clicking one filters everything to it (the
 * source-IP filter, which matches either end of a flow); clicking it again
 * clears the filter.
 */
export default function TopTalkers({ talkers, selected, onSelect }: Props) {
  if (talkers.length === 0) return null
  return (
    <Card data-testid="top-talkers">
      <CardHeader title="Top talkers" description="The busiest addresses by bytes. Click one to filter to it." />
      <div className="grid grid-cols-1 gap-3 border-t border-gray-100 dark:border-gray-800 p-6 sm:grid-cols-2 sm:p-6 xl:grid-cols-5">
        {talkers.map((t) => {
          const active = selected === t.ip
          return (
            <button
              key={t.ip}
              type="button"
              data-testid="top-talker"
              data-ip={t.ip}
              aria-pressed={active}
              onClick={() => onSelect(active ? '' : t.ip)}
              title={active ? `Stop filtering to ${t.ip}` : `Show only traffic of ${t.ip}`}
              className={`min-w-0 rounded-xl border p-3 text-left transition-colors ${
                active
                  ? 'border-brand-500 bg-brand-25 dark:bg-brand-500/10 ring-1 ring-brand-500'
                  : 'border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800/60'
              }`}
            >
              <div className="truncate font-mono text-theme-sm font-semibold text-gray-800 dark:text-white/90">{t.ip}</div>
              <div className="mt-1 text-theme-sm text-gray-600 dark:text-gray-400">{formatBytes(t.bytes)}</div>
              <div className="text-theme-xs text-gray-500 dark:text-gray-400">
                {t.packets.toLocaleString()} pkts · {t.flows.toLocaleString()} {t.flows === 1 ? 'flow' : 'flows'}
              </div>
            </button>
          )
        })}
      </div>
    </Card>
  )
}
