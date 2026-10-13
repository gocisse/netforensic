import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { memo, useCallback, useDeferredValue, useMemo, useRef, useState } from 'react'
import { protocolColor, severityColor } from '../../format'
import { useScrollMargin } from '../../hooks/useScrollMargin'
import { affectedIPs, matchesIssueSearch, sortIssues } from '../../issueView'
import type { IssueSortKey } from '../../issueView'
import { LIST_MAX, LIST_STEP } from '../../listCap'
import type { SortDir } from '../../goodTraffic'
import type { Issue } from '../../types'
import type { Affected } from '../../wireshark'
import IssueDetailsModal from '../IssueDetailsModal'
import AllClear from '../ui/AllClear'
import Badge from '../ui/Badge'
import Button from '../ui/Button'
import { Card, CardHeader } from '../ui/Card'
import { TableSkeleton } from '../ui/Skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/Table'

/** The height of a row in px before it is drawn and measured. */
const ROW_HEIGHT = 53

const COLUMNS: { key: IssueSortKey; label: string; right?: boolean }[] = [
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Issue' },
  { key: 'count', label: 'Count', right: true },
  { key: 'ips', label: 'Affected IPs' },
  { key: 'protocol', label: 'Protocol' },
]

interface Props {
  /** The issues that match the page's filters. */
  issues: Issue[]
  /** How many issues the capture has in all, for the "Showing X of Y" line. */
  total: number
  /** Whether filters are set: an empty table then says that no results match them. */
  filtered: boolean
  onClearFilters: () => void
  captureName: string
  onFilterTo: (endpoints: Affected['endpoints']) => void
  /** The issues are still arriving: an empty list is not "all clear" yet. */
  loading?: boolean
}

/** The addresses of an issue: its first two, and how many more there are. */
function Addresses({ issue }: { issue: Issue }) {
  const { labels, total } = affectedIPs(issue, 50)
  if (labels.length === 0) return <span className="text-gray-500 dark:text-gray-400">–</span>
  const first = labels.slice(0, 2)
  const more = total - first.length
  return (
    <span data-testid="issue-ips" className="block max-w-md truncate font-mono text-theme-xs text-gray-800 dark:text-white/90" title={labels.join('\n')}>
      {first.join(', ')}
      {more > 0 && <span className="text-gray-500 dark:text-gray-400">, +{more.toLocaleString()} more</span>}
    </span>
  )
}

const IssueRowView = memo(function IssueRowView({ issue, index, measure, onOpen }: { issue: Issue; index: number; measure: (el: HTMLTableRowElement | null) => void; onOpen: (i: Issue) => void }) {
  const count = Math.max(issue.count ?? 1, 1)
  const protocols = issue.protocols ?? []
  return (
    <TableRow
      data-testid="issue-row"
      data-severity={issue.severity}
      data-index={index}
      ref={measure}
      className="cursor-pointer"
      tabIndex={0}
      aria-haspopup="dialog"
      onClick={() => onOpen(issue)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen(issue)
        }
      }}
    >
      <TableCell className="whitespace-nowrap">
        <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
      </TableCell>
      <TableCell className="max-w-sm font-medium text-gray-800 dark:text-white/90">
        <span className="line-clamp-2" data-testid="issue-title" title={issue.title}>
          {issue.title}
        </span>
      </TableCell>
      <TableCell className="whitespace-nowrap text-right tabular-nums" data-testid="issue-count">
        ×{count.toLocaleString()}
      </TableCell>
      <TableCell>
        <Addresses issue={issue} />
      </TableCell>
      <TableCell className="whitespace-nowrap">
        {protocols.length > 0 ? (
          protocols.slice(0, 2).map((p) => (
            <span key={p} className={`mr-1 rounded px-2 py-1 text-theme-xs font-medium ${protocolColor(p).badge}`}>
              {p}
            </span>
          ))
        ) : (
          <span className="text-gray-500 dark:text-gray-400">–</span>
        )}
      </TableCell>
    </TableRow>
  )
})

/**
 * The issues as a table like the one of the flows with issues: severity,
 * title, number of events, the addresses involved and the protocol, the worst
 * first. Click a column to sort, type to search, click a row for the details
 * in a dialog. The rows are virtual (only those in view are drawn, and a very
 * long table shows its first 5,000 rows, with a button for more), so hundreds
 * of thousands of issues scroll as smoothly as a few.
 */
export default function IssuesTable({ issues, total, filtered, onClearFilters, captureName, onFilterTo, loading = false }: Props) {
  const [query, setQuery] = useState('')
  const deferred = useDeferredValue(query)
  const [sort, setSort] = useState<{ key: IssueSortKey; dir: SortDir }>({ key: 'severity', dir: 'desc' })
  const [limit, setLimit] = useState(LIST_STEP)
  const [open, setOpen] = useState<Issue | null>(null)
  const close = useCallback(() => setOpen(null), [])

  const rows = useMemo(() => sortIssues(issues.filter((i) => matchesIssueSearch(i, deferred)), sort.key, sort.dir), [issues, deferred, sort])
  const shown = Math.min(limit, LIST_MAX)
  const visible = useMemo(() => (rows.length > shown ? rows.slice(0, shown) : rows), [rows, shown])

  // The table is virtual: only the rows in view are drawn, between two spacer rows that keep the scroll height.
  const bodyTop = useRef<HTMLTableRowElement>(null)
  const scrollMargin = useScrollMargin(bodyTop)
  // The React Compiler is not used here, so the library's un-memoizable functions are fine.
  // oxlint-disable-next-line react/incompatible-library
  const virtualizer = useWindowVirtualizer({ count: visible.length, estimateSize: () => ROW_HEIGHT, getItemKey: (i) => visible[i].id, overscan: 8, scrollMargin })
  const drawn = virtualizer.getVirtualItems()
  const padTop = drawn.length > 0 ? drawn[0].start - scrollMargin : 0
  const padBottom = drawn.length > 0 ? virtualizer.getTotalSize() - (drawn[drawn.length - 1].end - scrollMargin) : 0
  const measure = virtualizer.measureElement

  const toggleSort = (key: IssueSortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'severity' || key === 'count' ? 'desc' : 'asc' }))
  }

  if (issues.length === 0 && loading) {
    return <TableSkeleton title="Issues" rows={4} testId="skeleton-issues" />
  }
  if (issues.length === 0) {
    return filtered ? (
      <Card>
        <div className="px-6 py-8 text-center" data-testid="issues-empty">
          <p className="text-base font-medium text-gray-800 dark:text-white/90">No results match your filters</p>
          <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">Remove a filter, or clear them all to see every issue again.</p>
          <Button variant="outline" size="sm" className="mt-3" onClick={onClearFilters} data-testid="empty-clear-filters">
            Clear filters
          </Button>
        </div>
      </Card>
    ) : (
      <Card>
        <AllClear testId="all-clear" title="All clear! No network issues detected." detail="Nothing in this capture needs attention. The Good Traffic tab lists its flows." />
      </Card>
    )
  }

  return (
    <Card data-testid="issue-groups">
      <CardHeader
        title="Issues"
        description={
          <span data-testid="filter-summary">
            Showing {rows.length.toLocaleString()} of {total.toLocaleString()} {total === 1 ? 'issue' : 'issues'}
            {loading && <span className="font-normal"> (still loading)</span>}
          </span>
        }
      />
      <div className="border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
        <label htmlFor="issue-search" className="mb-2 block text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
          Search issues
        </label>
        <input
          id="issue-search"
          data-testid="issue-search"
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="A title, an address or a word from the description"
          autoComplete="off"
          spellCheck={false}
          className="h-10 w-full max-w-lg rounded-lg border border-gray-300 dark:border-gray-700 bg-transparent dark:bg-gray-900 px-3 text-sm text-gray-800 dark:text-white/90 placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
        />
      </div>
      {rows.length === 0 ? (
        <div className="border-t border-gray-100 dark:border-gray-800 px-6 py-8 text-center" data-testid="issues-no-match">
          <p className="text-base font-medium text-gray-800 dark:text-white/90">No issues match your search</p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => setQuery('')}>
            Clear search
          </Button>
        </div>
      ) : (
        <div className="relative overflow-x-auto" data-testid="issue-list" data-total={visible.length}>
          <Table>
            <TableHeader>
              <TableRow>
                {COLUMNS.map((c) => (
                  <TableHead key={c.key} className={c.right ? 'text-right' : ''} aria-sort={sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                    <button type="button" onClick={() => toggleSort(c.key)} data-testid={`issue-sort-${c.key}`} className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-gray-800 dark:hover:text-white/90">
                      {c.label}
                      <span aria-hidden="true">{sort.key === c.key ? (sort.dir === 'asc' ? '▲' : '▼') : ''}</span>
                    </button>
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              <tr ref={bodyTop} aria-hidden="true" style={{ height: padTop }}>
                <td colSpan={COLUMNS.length} className="p-0" />
              </tr>
              {drawn.map((v) => (
                <IssueRowView key={visible[v.index].id} issue={visible[v.index]} index={v.index} measure={measure} onOpen={setOpen} />
              ))}
              <tr aria-hidden="true" style={{ height: padBottom }}>
                <td colSpan={COLUMNS.length} className="p-0" />
              </tr>
            </TableBody>
          </Table>
        </div>
      )}
      {rows.length > shown && (
        <div className="space-y-3 border-t border-gray-100 dark:border-gray-800 p-4 text-center sm:p-6" data-testid="list-capped">
          <p className="text-theme-sm text-gray-600 dark:text-gray-400">
            Showing the first {shown.toLocaleString()} of {rows.length.toLocaleString()} issues, sorted as chosen. {shown >= LIST_MAX ? 'Narrow the list with the filters or the search, or export all of it as CSV.' : ''}
          </p>
          {shown < LIST_MAX && (
            <Button variant="outline" size="sm" data-testid="list-show-more" onClick={() => setLimit((l) => Math.min(l + LIST_STEP, LIST_MAX))}>
              Show {Math.min(LIST_STEP, rows.length - shown, LIST_MAX - shown).toLocaleString()} more
            </Button>
          )}
        </div>
      )}
      {open && <IssueDetailsModal issue={open} captureName={captureName} onClose={close} onFilterTo={onFilterTo} />}
    </Card>
  )}
