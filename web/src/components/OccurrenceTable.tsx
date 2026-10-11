import { useMemo, useRef, useState } from 'react'
import { formatTime, formatValue, protocolColor, subjectLabel } from '../format'
import type { Issue, Occurrence } from '../types'

const ROW_HEIGHT = 32 // px; fixed, so that rows can be windowed
const VIEWPORT_HEIGHT = 320 // px
const OVERSCAN = 8 // rows rendered beyond the visible ones

type SortKey = 'time' | 'protocol' | 'subject' | 'value'
type SortDir = 'asc' | 'desc'

function compare(a: Occurrence, b: Occurrence, key: SortKey): number {
  switch (key) {
    case 'time':
      return Date.parse(a.time) - Date.parse(b.time) || 0
    case 'value':
      return (a.value ?? -Infinity) - (b.value ?? -Infinity)
    case 'protocol':
      return (a.protocol ?? '').localeCompare(b.protocol ?? '')
    default:
      return a.subject.localeCompare(b.subject)
  }
}

interface Props {
  issue: Issue
  occurrences: Occurrence[]
}

/**
 * A scrollable, sortable, filterable table of the events behind an
 * aggregated issue. Only the rows in view are rendered, so thousands of
 * occurrences scroll smoothly.
 */
export default function OccurrenceTable({ issue, occurrences }: Props) {
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir } | null>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const viewport = useRef<HTMLDivElement>(null)

  // Columns follow the data: a value column only if some event has a value.
  const hasValue = occurrences.some((o) => o.value !== undefined)
  const hasProtocol = occurrences.some((o) => o.protocol)
  const columns = hasProtocol
    ? hasValue
      ? 'grid-cols-[12rem_5rem_1fr_9rem]'
      : 'grid-cols-[12rem_5rem_1fr]'
    : hasValue
      ? 'grid-cols-[12rem_1fr_9rem]'
      : 'grid-cols-[12rem_1fr]'

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const list = needle ? occurrences.filter((o) => o.subject.toLowerCase().includes(needle)) : occurrences
    if (!sort) return list
    const sign = sort.dir === 'asc' ? 1 : -1
    return [...list].sort((a, b) => sign * compare(a, b, sort.key))
  }, [occurrences, filter, sort])

  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const last = Math.min(rows.length, Math.ceil((scrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) + OVERSCAN)
  const visible = rows.slice(first, last)

  const backToTop = () => {
    setScrollTop(0)
    if (viewport.current) viewport.current.scrollTop = 0
  }

  const toggleSort = (key: SortKey) => {
    // First click: the natural order for the column (largest value first,
    // otherwise A to Z or oldest first); second: reversed; third: as sent.
    const natural: SortDir = key === 'value' ? 'desc' : 'asc'
    setSort((s) => {
      if (s?.key !== key) return { key, dir: natural }
      if (s.dir === natural) return { key, dir: natural === 'asc' ? 'desc' : 'asc' }
      return null
    })
    backToTop()
  }

  const heading = (key: SortKey, label: string) => {
    const active = sort?.key === key
    return (
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className="flex items-center gap-1 text-left font-semibold uppercase tracking-wide hover:text-gray-900 dark:hover:text-white"
        aria-label={`Sort by ${label}`}
      >
        {label}
        <span aria-hidden="true" className="text-[10px]">
          {active ? (sort.dir === 'asc' ? '▲' : '▼') : ''}
        </span>
      </button>
    )
  }

  return (
    <div data-testid="occurrence-table" className="mt-3 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 dark:border-gray-800 px-3 py-2">
        <input
          type="search"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value)
            backToTop()
          }}
          placeholder={`Filter by ${subjectLabel(issue).toLowerCase()}…`}
          aria-label={`Filter by ${subjectLabel(issue).toLowerCase()}`}
          className="w-64 h-9 rounded-lg border border-gray-300 dark:border-gray-700 px-3 text-theme-sm focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
        />
        <span data-testid="occurrence-count" className="text-theme-xs text-gray-500 dark:text-gray-400">
          {filter.trim()
            ? `Showing ${rows.length.toLocaleString()} of ${occurrences.length.toLocaleString()}`
            : `${occurrences.length.toLocaleString()} ${occurrences.length === 1 ? 'event' : 'events'}`}
        </span>
      </div>

      <div
        role="row"
        className={`grid ${columns} gap-3 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60 px-3 py-2 text-theme-xs text-gray-500 dark:text-gray-400`}
      >
        {heading('time', 'Time (UTC)')}
        {hasProtocol && heading('protocol', 'Protocol')}
        {heading('subject', subjectLabel(issue))}
        {hasValue && heading('value', 'Value')}
      </div>

      <div
        ref={viewport}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        style={{ height: Math.min(VIEWPORT_HEIGHT, Math.max(rows.length, 1) * ROW_HEIGHT) }}
        className="overflow-y-auto"
        role="rowgroup"
        tabIndex={0}
        aria-label="Occurrences"
      >
        {rows.length === 0 ? (
          <p className="px-3 py-2 text-theme-sm text-gray-500 dark:text-gray-400">No events match the filter.</p>
        ) : (
          <div style={{ height: rows.length * ROW_HEIGHT, position: 'relative' }}>
            {visible.map((o, i) => (
              <div
                key={first + i}
                role="row"
                data-testid="occurrence-row"
                style={{ position: 'absolute', top: (first + i) * ROW_HEIGHT, height: ROW_HEIGHT, left: 0, right: 0 }}
                className={`grid ${columns} items-center gap-3 px-3 text-sm even:bg-gray-50/60 dark:even:bg-white/[0.03]`}
              >
                <span className="whitespace-nowrap font-mono text-xs text-gray-600 dark:text-gray-400">{formatTime(o.time)}</span>
                {hasProtocol && (
                  <span data-testid="occurrence-protocol">
                    {o.protocol && (
                      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${protocolColor(o.protocol).badge}`}>
                        {o.protocol}
                      </span>
                    )}
                  </span>
                )}
                <span className="truncate font-mono text-xs text-gray-900 dark:text-white" title={o.subject}>
                  {o.subject}
                </span>
                {hasValue && (
                  <span className="whitespace-nowrap text-right font-mono text-xs text-gray-700 dark:text-gray-300">{formatValue(o)}</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
