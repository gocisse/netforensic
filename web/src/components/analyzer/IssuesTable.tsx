import { useReveal } from '../../hooks/useReveal'
import { Fragment, useMemo, useState } from 'react'
import { protocolColor, severityColor } from '../../format'
import type { Issue, Severity } from '../../types'
import OccurrenceTable from '../OccurrenceTable'
import IssueGuidance from './IssueGuidance'
import Badge from '../ui/Badge'
import AllClear from '../ui/AllClear'
import Button from '../ui/Button'
import Collapse from '../ui/Collapse'

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/Table'
import MonoText from '../ui/MonoText'

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
  /** Whether filters are set, for the empty message. */
  filtered: boolean
  /** Clears the filters; offered by the empty message when they are set. */
  onClearFilters?: () => void
  /** The capture's file name, for the Wireshark commands. */
  captureName: string
}

interface DetailsProps {
  issue: Issue
  show: boolean
  captureName: string
}

/** The drill-down row of an issue: it slides open and shut, and is not in the table while shut. */
function DetailsRow({ issue, show, captureName }: DetailsProps) {
  const { mounted, open } = useReveal(show)
  if (!mounted) return null
  const occurrences = issue.occurrences ?? []
  return (
    <TableRow data-testid="issue-details">
      <TableCell colSpan={5} className="bg-gray-50/60 dark:bg-white/[0.03] !p-0">
        <Collapse open={open}>
          <div className="space-y-4 px-4 pb-4 pt-3">
            <IssueGuidance issue={issue} captureName={captureName} />
            {occurrences.length > 0 && <OccurrenceTable issue={issue} occurrences={occurrences} />}
          </div>
        </Collapse>
      </TableCell>
    </TableRow>
  )
}

/** A sortable data table of issues; rows with events expand into a drill-down. */
export default function IssuesTable({ issues, filtered, onClearFilters, captureName }: Props) {
  const [showAll, setShowAll] = useState(false)
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'severity', dir: 'desc' })
  const [open, setOpen] = useState<Set<string>>(new Set())
  const [wide, setWide] = useState<Set<string>>(new Set()) // issues whose description is shown in full

  const rows = useMemo(() => {
    const sign = sort.dir === 'asc' ? 1 : -1
    return [...issues].sort((a, b) => sign * compare(a, b, sort.key))
  }, [issues, sort])

  if (rows.length === 0) {
    if (!filtered) {
      return (
        <div data-testid="no-issues">
          <AllClear />
        </div>
      )
    }
    return (
      <div className="px-4 py-8 text-center" data-testid="no-issues">
        <p className="text-base font-medium text-gray-800 dark:text-white/90">No results match your filters</p>
        <p className="mt-1 text-theme-sm text-gray-600 dark:text-gray-400">Remove a filter, or clear them all to see every issue again.</p>
        {onClearFilters && (
          <Button variant="outline" size="sm" className="mt-3" onClick={onClearFilters} data-testid="empty-clear-filters">
            Clear filters
          </Button>
        )}
      </div>
    )
  }

  const shown = showAll ? rows : rows.slice(0, TOP_ISSUES)

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'severity' || key === 'count' ? 'desc' : 'asc' }))

  const flip = (set: (f: (prev: Set<string>) => Set<string>) => void, id: string) =>
    set((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const toggleOpen = (id: string) => flip(setOpen, id)
  const toggleWide = (id: string) => flip(setWide, id)

  const heading = (key: SortKey, label: string, className = '') => {
    const active = sort.key === key
    return (
      <TableHead className={className} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button
          type="button"
          onClick={() => toggleSort(key)}
          aria-label={`Sort issues by ${label}`}
          className="inline-flex items-center gap-1 font-medium uppercase tracking-wide hover:text-gray-800 dark:hover:text-white/90"
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
              const expanded = open.has(issue.id)
              return (
                <Fragment key={issue.id}>
                  <TableRow
                    data-testid="issue-row"
                    className="cursor-pointer align-top hover:bg-gray-50/60 dark:hover:bg-white/[0.03]"
                    onClick={(e) => {
                      // a click on the row (not on a button or link in it) shows or hides the full description
                      if ((e.target as HTMLElement).closest('button, a')) return
                      toggleWide(issue.id)
                    }}
                  >
                    <TableCell className="whitespace-nowrap">
                      <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-theme-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
                      {issue.category}
                    </TableCell>
                    <TableCell className="min-w-72 max-w-xl">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-gray-800 dark:text-white/90">{issue.title}</span>
                        {(issue.protocols ?? []).map((p) => (
                          <span key={p} className={`rounded px-2 py-1 text-[11px] font-medium ${protocolColor(p).badge}`}>
                            {p}
                          </span>
                        ))}
                      </div>
                      <p
                        data-testid="issue-description"
                        data-expanded={wide.has(issue.id)}
                        className={`mt-1 whitespace-pre-wrap break-words text-theme-xs text-gray-500 dark:text-gray-400 ${wide.has(issue.id) ? '' : 'line-clamp-2'}`}
                      >
                        <MonoText>{issue.description}</MonoText>
                      </p>
                      {issue.description.length > 140 || wide.has(issue.id) ? (
                        <button
                          type="button"
                          aria-expanded={wide.has(issue.id)}
                          onClick={() => toggleWide(issue.id)}
                          className="mt-1 text-theme-xs font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300"
                        >
                          {wide.has(issue.id) ? 'Show less' : 'Show full description'}
                        </button>
                      ) : null}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right tabular-nums">
                      {(issue.count ?? 1) > 1 ? <span className="rounded-full bg-gray-100 dark:bg-gray-800 px-2 py-1 text-theme-xs text-gray-600 dark:text-gray-400">×{issue.count}</span> : ''}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        className="px-3 py-2 text-xs"
                        aria-expanded={expanded}
                        data-testid="issue-details-toggle"
                        onClick={() => toggleOpen(issue.id)}
                      >
                        {expanded ? 'Hide details' : occurrences.length > 0 ? `View details (${occurrences.length.toLocaleString()})` : 'View details'}
                      </Button>
                    </TableCell>
                  </TableRow>
                  <DetailsRow issue={issue} show={expanded} captureName={captureName} />
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
      </div>
      {rows.length > TOP_ISSUES && (
        <div className="border-t border-gray-100 dark:border-gray-800 px-4 py-3">
          <button type="button" onClick={() => setShowAll((v) => !v)} className="text-theme-sm font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">
            {showAll ? `Show the top ${TOP_ISSUES} only` : `Show all ${rows.length} issues`}
          </button>
        </div>
      )}
    </div>
  )
}
