import { useState } from 'react'
import { protocolColor, severityColor } from '../../format'
import type { Issue } from '../../types'
import { affectedOf } from '../../wireshark'
import type { Affected } from '../../wireshark'
import OccurrenceTable from '../OccurrenceTable'
import Badge from '../ui/Badge'
import Button from '../ui/Button'
import Reveal from '../ui/Reveal'
import { Card } from '../ui/Card'
import IssueGuidance from './IssueGuidance'
import MonoText from '../ui/MonoText'

const SHOWN = 5

export interface Props {
  issue: Issue
  captureName: string
  /** Called with the addresses of an affected flow when it is clicked, to filter to it. */
  onFilterTo: (endpoints: Affected['endpoints']) => void
}

/**
 * One issue in full: its severity and title, the description, the flows it
 * affects (click one to filter to it), what to do about it, and the Wireshark
 * filter that shows its packets, with buttons to copy it. The events behind an
 * aggregated issue open below.
 */
export default function SeniorIssueCard({ issue, captureName, onFilterTo }: Props) {
  const [showAll, setShowAll] = useState(false)
  const [events, setEvents] = useState(false)
  const affected = affectedOf(issue)
  const shown = showAll ? affected : affected.slice(0, SHOWN)
  const occurrences = issue.occurrences ?? []

  return (
    <Card data-testid="issue-card" className="overflow-hidden transition-shadow duration-200 hover:shadow-theme-md">
      <div className="space-y-4 p-6 sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
          <h3 className="text-base font-semibold text-gray-800 dark:text-white/90" data-testid="issue-card-title">
            {issue.title}
          </h3>
          {(issue.protocols ?? []).map((p) => (
            <span key={p} className={`rounded px-2 py-1 text-[11px] font-medium ${protocolColor(p).badge}`}>
              {p}
            </span>
          ))}
          {(issue.count ?? 1) > 1 && <span className="rounded-full bg-gray-100 dark:bg-gray-800 px-2 py-1 text-theme-xs text-gray-600 dark:text-gray-400">×{issue.count}</span>}
        </div>

        <p className="whitespace-pre-wrap break-words text-theme-sm text-gray-600 dark:text-gray-400" data-testid="issue-card-description">
          <MonoText>{issue.description}</MonoText>
        </p>

        {affected.length > 0 && (
          <div data-testid="affected">
            <p className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Affected</p>
            <ul className="flex flex-wrap gap-2">
              {shown.map((a) => {
                const clickable = a.endpoints.length > 0
                return (
                  <li key={a.label}>
                    {clickable ? (
                      <button
                        type="button"
                        data-testid="affected-flow"
                        onClick={() => onFilterTo(a.endpoints)}
                        title="Filter the page to this flow"
                        className="max-w-full truncate rounded-lg border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60 px-3 py-1 font-mono text-theme-xs text-gray-800 dark:text-white/90 hover:border-brand-500 hover:text-brand-700 dark:hover:text-brand-300"
                      >
                        {a.label}
                      </button>
                    ) : (
                      <span data-testid="affected-name" className="inline-block font-mono max-w-full truncate rounded-lg bg-gray-50 dark:bg-gray-800/60 px-3 py-1 text-theme-xs text-gray-700 dark:text-gray-300" title={a.label}>
                        {a.label}
                      </span>
                    )}
                  </li>
                )
              })}
              {affected.length > SHOWN && (
                <li>
                  <button type="button" onClick={() => setShowAll((v) => !v)} className="px-2 py-1 text-theme-xs font-medium text-brand-600 dark:text-brand-400 hover:text-brand-600">
                    {showAll ? 'Show fewer' : `+${affected.length - SHOWN} more`}
                  </button>
                </li>
              )}
            </ul>
          </div>
        )}

        <IssueGuidance issue={issue} captureName={captureName} />

        {occurrences.length > 0 && (
          <div>
            <Button variant="outline" size="sm" className="px-3 py-2 text-xs" aria-expanded={events} data-testid="issue-card-events" onClick={() => setEvents((v) => !v)}>
              {events ? 'Hide events' : `Show events (${occurrences.length.toLocaleString()})`}
            </Button>
            <Reveal show={events} testId="issue-card-events-panel">
              <div className="pt-3">
                <OccurrenceTable issue={issue} occurrences={occurrences} />
              </div>
            </Reveal>
          </div>
        )}
      </div>
    </Card>
  )
}
