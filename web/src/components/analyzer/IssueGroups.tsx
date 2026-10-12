import { useMemo } from 'react'
import { groupBySeverity, issueRows } from '../../issueView'
import type { IssueRow } from '../../issueView'
import type { Issue } from '../../types'
import type { Affected } from '../../wireshark'
import AllClear from '../ui/AllClear'
import { TableSkeleton } from '../ui/Skeleton'
import Button from '../ui/Button'
import { Card } from '../ui/Card'
import VirtualList from '../ui/VirtualList'
import IssueCard from './IssueCard'

const HEADING: Record<string, string> = {
  CRITICAL: 'text-error-700 dark:text-error-400',
  ERROR: 'text-error-600 dark:text-error-400',
  WARNING: 'text-warning-700 dark:text-warning-400',
  INFO: 'text-blue-light-700 dark:text-blue-light-400',
}

interface Props {
  issues: Issue[]
  /** Whether filters are set: an empty list then says that no results match them. */
  filtered: boolean
  onClearFilters: () => void
  captureName: string
  onFilterTo: (endpoints: Affected['endpoints']) => void
  /** The issues are still arriving: an empty list is not "all clear" yet. */
  loading?: boolean
}

const ROW_GAP = 16
const rowKey = (r: IssueRow) => (r.kind === 'heading' ? `heading-${r.severity}` : r.issue.id)
const rowHeight = (r: IssueRow) => (r.kind === 'heading' ? 48 : 440)

/**
 * The issues as cards, grouped by severity (the worst first), or the reason
 * there are none. The list is virtual: only the cards in view are drawn, so
 * hundreds of thousands of issues scroll as smoothly as a few.
 */
export default function IssueGroups({ issues, filtered, onClearFilters, captureName, onFilterTo, loading = false }: Props) {
  const rows = useMemo(() => issueRows(groupBySeverity(issues)), [issues])

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
    <div data-testid="issue-groups">
      <VirtualList
        items={rows}
        getKey={rowKey}
        estimate={rowHeight}
        gap={ROW_GAP}
        testId="issue-list"
        render={(row) =>
          row.kind === 'heading' ? (
            <h3
              id={`sev-${row.severity}`}
              data-testid="severity-heading"
              data-severity={row.severity}
              className={`pt-4 text-theme-sm font-semibold uppercase tracking-wide ${HEADING[row.severity]}`}
            >
              {row.severity} · {row.count.toLocaleString()} {row.count === 1 ? 'issue' : 'issues'}
            </h3>
          ) : (
            <IssueCard issue={row.issue} captureName={captureName} onFilterTo={onFilterTo} />
          )
        }
      />
    </div>
  )
}
