import { useState } from 'react'
import { sortIssues } from '../../format'
import { plainSeverity } from '../../plainLanguage'
import type { Issue } from '../../types'
import Button from '../ui/Button'
import { Card } from '../ui/Card'
import AllClear from '../ui/AllClear'
import JuniorIssueCard from './JuniorIssueCard'

const SHOWN = 5

interface Props {
  issues: Issue[]
  /** Heading above the list. */
  heading: string
  /** What to say when there are no issues: false for "all clear" (nothing wrong), true for "nothing here". */
  emptyIsNeutral?: boolean
  emptyText?: string
}

/** The issues as plain-language cards, the worst first, with a count by seriousness. */
export default function JuniorIssueList({ issues, heading, emptyIsNeutral = false, emptyText = 'Nothing to report here.' }: Props) {
  const [all, setAll] = useState(false)
  const sorted = sortIssues(issues)
  const shown = all ? sorted : sorted.slice(0, SHOWN)
  const counts = { error: 0, warning: 0, info: 0 }
  for (const i of issues) counts[plainSeverity(i.severity).kind]++

  return (
    <section className="space-y-4" data-testid="junior-issues">
      <div>
        <h2 className="text-xl font-semibold text-gray-800 dark:text-white/90">{heading}</h2>
        {issues.length > 0 && (
          <p className="mt-1 text-theme-sm text-gray-700 dark:text-gray-300" data-testid="junior-issue-summary">
            We found {issues.length.toLocaleString()} {issues.length === 1 ? 'problem' : 'problems'}
            {': '}
            {[counts.error > 0 && `${counts.error} serious`, counts.warning > 0 && `${counts.warning} that need${counts.warning === 1 ? 's' : ''} attention`, counts.info > 0 && `${counts.info} good to know`]
              .filter(Boolean)
              .join(', ')}
            .
          </p>
        )}
      </div>
      {issues.length === 0 ? (
        <Card>{emptyIsNeutral ? <p className="px-6 py-8 text-center text-theme-sm text-gray-700 dark:text-gray-300">{emptyText}</p> : <AllClear />}</Card>
      ) : (
        <>
          {shown.map((i) => (
            <JuniorIssueCard key={i.id} issue={i} />
          ))}
          {sorted.length > SHOWN && (
            <Button variant="outline" size="sm" onClick={() => setAll((v) => !v)} data-testid="junior-show-all">
              {all ? 'Show only the most important' : `Show all ${sorted.length.toLocaleString()} problems`}
            </Button>
          )}
        </>
      )}
    </section>
  )
}
