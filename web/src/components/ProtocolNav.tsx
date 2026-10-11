import { NavLink } from 'react-router-dom'
import { PROTOCOL_PAGES } from '../protocols'

interface Props {
  /** The analysis the tabs belong to. */
  id: string
  /** Issues per protocol, for the badges. */
  counts: Record<string, number>
  /** The query string to carry from page to page, so that the filters follow. */
  search: string
}

const tab = (active: boolean, dim: boolean) =>
  `inline-flex items-center gap-2 whitespace-nowrap rounded-lg border px-3.5 py-2 text-theme-sm font-medium transition-colors ${
    active
      ? 'border-brand-500 bg-brand-500 text-white'
      : `border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-800/60 ${
          dim ? 'text-gray-400 dark:text-gray-500' : 'text-gray-700 dark:text-gray-300'
        }`
  }`

/**
 * The tabs of an analysis: the overview and one page per protocol, each with
 * its number of issues. The active tab is highlighted.
 */
export default function ProtocolNav({ id, counts, search }: Props) {
  return (
    <nav aria-label="Protocols" data-testid="protocol-nav" className="-mx-1 overflow-x-auto px-1 pb-1">
      <ul className="flex gap-2">
        <li>
          <NavLink to={{ pathname: `/analysis/${id}`, search }} end data-testid="nav-overview" className={({ isActive }) => tab(isActive, false)}>
            Overview
          </NavLink>
        </li>
        {PROTOCOL_PAGES.map((p) => {
          const n = counts[p.protocol] ?? 0
          return (
            <li key={p.slug}>
              <NavLink to={{ pathname: `/analysis/${id}/${p.slug}`, search }} data-testid={`nav-${p.slug}`} className={({ isActive }) => tab(isActive, n === 0)}>
                {({ isActive }) => (
                  <>
                    {p.protocol}
                    <span
                      data-testid={`nav-count-${p.slug}`}
                      className={`rounded-full px-2 py-0.5 text-theme-xs font-semibold ${
                        isActive ? 'bg-white/25 text-white' : n > 0 ? 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300' : 'bg-gray-50 dark:bg-gray-800/50 text-gray-400'
                      }`}
                    >
                      {n}
                    </span>
                  </>
                )}
              </NavLink>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
