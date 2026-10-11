import type { FilterState } from '../filters/model'
import type { Filters } from '../filters/useFilters'
import { CloseIcon } from '../icons'

interface Tag {
  key: string
  label: string
  remove: Partial<FilterState>
}

/** The applied filters as tags, one per value, each removable. */
function tagsOf(f: FilterState): Tag[] {
  const tags: Tag[] = []
  if (f.sourceIp) tags.push({ key: 'src', label: `Source IP: ${f.sourceIp}`, remove: { sourceIp: '' } })
  if (f.destIp) tags.push({ key: 'dst', label: `Destination IP: ${f.destIp}`, remove: { destIp: '' } })
  if (f.port) tags.push({ key: 'port', label: `Port: ${f.port}`, remove: { port: '' } })
  if (f.protocol !== 'All') tags.push({ key: 'proto', label: `Protocol: ${f.protocol}`, remove: { protocol: 'All' } })
  for (const s of f.severities) tags.push({ key: `sev-${s}`, label: `Severity: ${s}`, remove: { severities: f.severities.filter((x) => x !== s) } })
  for (const c of f.categories) tags.push({ key: `cat-${c}`, label: `Category: ${c}`, remove: { categories: f.categories.filter((x) => x !== c) } })
  return tags
}

/** The applied filters as removable tags. Shows nothing when there are none. */
export default function ActiveFilters({ filters }: { filters: Filters }) {
  const tags = tagsOf(filters.applied)
  if (tags.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="active-filters" aria-label="Active filters">
      <span className="text-theme-sm font-medium text-gray-600 dark:text-gray-400">Active filters:</span>
      {tags.map((t) => (
        <span
          key={t.key}
          data-testid="filter-tag"
          className="inline-flex items-center gap-1 rounded-full bg-brand-50 dark:bg-brand-500/15 py-1 pl-3 pr-1 text-theme-sm font-medium text-brand-600 dark:text-brand-400"
        >
          {t.label}
          <button
            type="button"
            aria-label={`Remove filter ${t.label}`}
            onClick={() => filters.set(t.remove)}
            className="flex h-5 w-5 items-center justify-center rounded-full hover:bg-brand-100 dark:hover:bg-brand-500/25"
          >
            <CloseIcon className="h-3.5 w-3.5" />
          </button>
        </span>
      ))}
      <button type="button" onClick={filters.reset} data-testid="clear-filters" className="text-theme-sm font-medium text-gray-500 dark:text-gray-400 underline hover:text-gray-700 dark:hover:text-gray-200">
        Clear all
      </button>
    </div>
  )
}
