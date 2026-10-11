import { groupProtocols } from '../../plainLanguage'
import type { ProtocolStat } from '../../types'
import { Card, CardBody, CardHeader } from '../ui/Card'

/** What kinds of traffic the network carries, as a few labelled bars (no packet counts). */
export default function JuniorProtocolDistribution({ stats }: { stats: ProtocolStat[] }) {
  const shares = groupProtocols(stats)
  return (
    <Card data-testid="junior-distribution">
      <CardHeader title="What the network is used for" description="How much of the traffic belongs to each kind of use." />
      <CardBody>
        {shares.length === 0 ? (
          <p className="text-theme-sm text-gray-600 dark:text-gray-400">There is no traffic to show.</p>
        ) : (
          <ul className="space-y-4">
            {shares.map((s) => (
              <li key={s.key} data-testid="junior-group" data-group={s.key}>
                <div className="mb-1 flex items-baseline justify-between gap-4 text-theme-sm">
                  <span className="font-medium text-gray-800 dark:text-white/90">{s.label}</span>
                  <span className="text-gray-600 dark:text-gray-400 tabular-nums">{s.percent < 1 ? 'less than 1' : Math.round(s.percent)}%</span>
                </div>
                <div className="h-3 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800" role="img" aria-label={`${s.label}: ${Math.round(s.percent)} percent`}>
                  <div className={`h-full rounded-full ${s.bar}`} style={{ width: `${Math.max(s.percent, 1)}%` }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  )
}
