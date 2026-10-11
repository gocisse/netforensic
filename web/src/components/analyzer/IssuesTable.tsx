import { Fragment, useMemo, useState } from 'react'
import { protocolColor, severityColor } from '../../format'
import type { Issue, Severity } from '../../types'
import OccurrenceTable from '../OccurrenceTable'
import Badge from '../ui/Badge'
import Button from '../ui/Button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/Table'

const TOP_ISSUES = 10
const RANK: Record<Severity, number> = { CRITICAL: 3, ERROR: 2, WARNING: 1, INFO: 0 }

type SortKey = 'severity' | 'category' | 'title' | 'count'
type SortDir = 'asc' | 'desc'

function compare(a: Issue, b: Issue, key: SortKey): number {
  switch (key) {
    case 'severity':
      return RANK[a.severity] - RANK[b.severity] || (a.count ?? 1) - (b.count ?? 1)
    case 'category':
      return a.category.localeCompare(b.category)
    case 'title':
      return a.title.localeCompare(b.title)
    default:
      return (a.count ?? 1) - (b.count ?? 1)
  }
}

interface Props {
  issues: Issue[]
  /** The selected protocol filter, for the empty message. */
  filter: string
}

/** A sortable data table of issues; rows with events expand into a drill-down. */
export default function IssuesTable({ issues, filter }: Props) {
  const [showAll, setShowAll] = useState(false)
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'severity', dir: 'desc' })
  const [open, setOpen] = useState<Set<string>>(new Set())

  const rows = useMemo(() => {
    const sign = sort.dir === 'asc' ? 1 : -1
    return [...issues].sort((a, b) => sign * compare(a, b, sort.key))
  }, [issues, sort])

  if (rows.length === 0) {
    return (
      <p className="text-theme-sm text-gray-500" data-testid="no-issues">
        {filter === 'All' ? 'No issues were found in this capture.' : `No ${filter} issues were found in this capture.`}
      </p>
    )
  }

  const shown = showAll ? rows : rows.slice(0, TOP_ISSUES)

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'severity' || key === 'count' ? 'desc' : 'asc' }))

  const toggleOpen = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const heading = (key: SortKey, label: string, className = '') => {
    const active = sort.key === key
    return (
      <TableHead className={className} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button
          type="button"
          onClick={() => toggleSort(key)}
          aria-label={`Sort issues by ${label}`}
          className="inline-flex items-center gap-1 font-medium uppercase tracking-wide hover:text-gray-800"
        >
          {label}
          <span aria-hidden="true" className="w-2 text-[10px]">
            {active ? (sort.dir === 'asc' ? '▲' : '▼') : ''}
          </span>
        </button>
      </TableHead>
    )
  }

  return (
    <div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              {heading('severity', 'Severity')}
              {heading('category', 'Category')}
              {heading('title', 'Issue')}
              {heading('count', 'Events', 'text-right')}
              <TableHead className="text-right">Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map((issue) => {
              const occurrences = issue.occurrences ?? []
              const expanded = open.has(issue.id) && occurrences.length > 0
              return (
                <Fragment key={issue.id}>
                  <TableRow data-testid="issue-row" className="align-top hover:bg-gray-50/60">
                    <TableCell className="whitespace-nowrap">
                      <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-theme-xs font-medium uppercase tracking-wide text-gray-500">
                      {issue.category}
                    </TableCell>
                    <TableCell className="min-w-72 max-w-xl">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-gray-800">{issue.title}</span>
                        {(issue.protocols ?? []).map((p) => (
                          <span key={p} className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${protocolColor(p).badge}`}>
                            {p}
                          </span>
                        ))}
                      </div>
                      <p className="mt-1 line-clamp-2 text-theme-xs text-gray-500" title={issue.description}>
                        {issue.description}
                      </p>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right tabular-nums">
                      {(issue.count ?? 1) > 1 ? <span className="rounded-full bg-gray-100 px-2 py-0.5 text-theme-xs text-gray-600">×{issue.count}</span> : ''}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right">
                      {occurrences.length > 0 && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="px-3 py-1.5 text-xs"
                          aria-expanded={expanded}
                          onClick={() => toggleOpen(issue.id)}
                        >
                          {expanded ? 'Hide details' : `View details (${occurrences.length.toLocaleString()})`}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                  {expanded && (
                    <TableRow data-testid="issue-details">
                      <TableCell colSpan={5} className="bg-gray-50/60 pb-4 pt-0">
                        <OccurrenceTable issue={issue} occurrences={occurrences} />
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
      </div>
      {rows.length > TOP_ISSUES && (
        <div className="border-t border-gray-100 px-4 py-3">
          <button type="button" onClick={() => setShowAll((v) => !v)} className="text-theme-sm font-medium text-brand-500 hover:text-brand-600">
            {showAll ? `Show the top ${TOP_ISSUES} only` : `Show all ${rows.length} issues`}
          </button>
        </div>
      )}
    </div>
  )
}
