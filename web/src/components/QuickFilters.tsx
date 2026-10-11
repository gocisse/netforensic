import type { FilterState } from '../filters/model'
import type { Filters } from '../filters/useFilters'

interface Quick {
  label: string
  testId: string
  /** The filters the shortcut sets. */
  patch: Partial<FilterState>
  /** Whether the shortcut is in force right now. */
  isOn: (f: FilterState) => boolean
  /** What clicking it again undoes. */
  off: Partial<FilterState>
}

const only = (list: string[], value: string) => list.length === 1 && list[0] === value

const QUICK: Quick[] = [
  { label: 'All Errors', testId: 'quick-errors', patch: { severities: ['ERROR'] }, isOn: (f) => only(f.severities, 'ERROR'), off: { severities: [] } },
  { label: 'DNS Issues', testId: 'quick-dns', patch: { categories: ['DNS'] }, isOn: (f) => only(f.categories, 'DNS'), off: { categories: [] } },
  { label: 'Connection Issues', testId: 'quick-connection', patch: { categories: ['Connection'] }, isOn: (f) => only(f.categories, 'Connection'), off: { categories: [] } },
  { label: 'Packet Loss', testId: 'quick-packetloss', patch: { categories: ['PacketLoss'] }, isOn: (f) => only(f.categories, 'PacketLoss'), off: { categories: [] } },
]

/**
 * One-click troubleshooting shortcuts. Each sets one filter (the severity or
 * the category) and leaves the others as they are; clicking it again clears it.
 */
export default function QuickFilters({ filters }: { filters: Filters }) {
  return (
    <div data-testid="quick-filters">
      <p className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">Quick filters</p>
      <div className="flex flex-wrap gap-2">
        {QUICK.map((q) => {
          const on = q.isOn(filters.applied)
          return (
            <button
              key={q.testId}
              type="button"
              data-testid={q.testId}
              aria-pressed={on}
              onClick={() => filters.set(on ? q.off : q.patch)}
              className={`rounded-full border px-4 py-2 text-theme-sm font-medium transition-colors ${
                on
                  ? 'border-brand-500 bg-brand-500 text-white'
                  : 'border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800/60'
              }`}
            >
              {q.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}
