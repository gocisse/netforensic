import { Link, useLocation } from 'react-router-dom'

interface Props {
  /** The analysis the tabs belong to. */
  id: string
  issues: number
  goodFlows: number
  /** The query string to carry from tab to tab, so that the filters follow. */
  search: string
}

const tab = (active: boolean) =>
  `flex h-full items-center justify-center gap-2 border-b-2 px-3 py-3 text-center text-theme-sm font-semibold transition-colors sm:px-4 ${
    active ? 'border-brand-500 text-brand-600 dark:text-brand-400' : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white/90'
  }`

/**
 * The top-level split of an analysis: Bad Traffic (the issues, with a page per
 * protocol beneath) and Good Traffic (the flows no issue names). Bad Traffic is
 * the active tab on every page but Good Traffic.
 */
export default function TrafficTabs({ id, issues, goodFlows, search }: Props) {
  const { pathname } = useLocation()
  const good = pathname.replace(/\/$/, '').endsWith('/good')
  return (
    <nav aria-label="Traffic" data-testid="traffic-tabs" className="border-b border-gray-200 dark:border-gray-800">
      <ul className="-mb-px flex gap-2">
        <li className="flex-1 sm:flex-none">
          <Link to={{ pathname: `/analysis/${id}/bad`, search }} data-testid="tab-bad" aria-current={good ? undefined : 'page'} className={tab(!good)}>
            <span aria-hidden="true">🔴</span>
            Bad Traffic ({issues.toLocaleString()} {issues === 1 ? 'issue' : 'issues'})
          </Link>
        </li>
        <li className="flex-1 sm:flex-none">
          <Link to={{ pathname: `/analysis/${id}/good`, search }} data-testid="tab-good" aria-current={good ? 'page' : undefined} className={tab(good)}>
            <span aria-hidden="true">🟢</span>
            Good Traffic ({goodFlows.toLocaleString()} {goodFlows === 1 ? 'flow' : 'flows'})
          </Link>
        </li>
      </ul>
    </nav>
  )
}
