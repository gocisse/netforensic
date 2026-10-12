import { useMemo } from 'react'
import { useDrawn } from '../../hooks/useDrawn'
import { groupBySeverity } from '../../issueView'
import type { Issue } from '../../types'
import type { Affected } from '../../wireshark'
import AllClear from '../ui/AllClear'
import Button from '../ui/Button'
import { Card } from '../ui/Card'
import DrawMore from '../ui/DrawMore'
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
}

/** The issues as cards, grouped by severity (the worst first), or the reason there are none. */
export default function IssueGroups({ issues, filtered, onClearFilters, captureName, onFilterTo }: Props) {
  const groups = useMemo(() => groupBySeverity(issues), [issues])

  const drawn = useDrawn(issues)
  const count = drawn.count

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
    <div className="space-y-8" data-testid="issue-groups">
      {groups.map((g, gi) => {
        const before = groups.slice(0, gi).reduce((n, x) => n + x.issues.length, 0)
        const visible = g.issues.slice(0, Math.max(0, count - before))
        if (visible.length === 0) return null
        return (
          <section key={g.severity} aria-labelledby={`sev-${g.severity}`} data-testid="severity-group" data-severity={g.severity} className="space-y-4">
            <h3 id={`sev-${g.severity}`} className={`text-theme-sm font-semibold uppercase tracking-wide ${HEADING[g.severity]}`}>
              {g.severity} · {g.issues.length.toLocaleString()} {g.issues.length === 1 ? 'issue' : 'issues'}
            </h3>
            {visible.map((issue) => (
              <IssueCard key={issue.id} issue={issue} captureName={captureName} onFilterTo={onFilterTo} />
            ))}
          </section>
        )
      })}
      <DrawMore drawn={drawn} />
    </div>
  )
}
