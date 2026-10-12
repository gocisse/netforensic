import { memo, useState } from 'react'
import { copyText } from '../../clipboard'
import { protocolColor, severityColor } from '../../format'
import { impactOf } from '../../issueView'
import { useToast } from '../../toast/useToast'
import type { Issue } from '../../types'
import { affectedOf, tsharkCommand } from '../../wireshark'
import type { Affected } from '../../wireshark'
import OccurrenceTable from '../OccurrenceTable'
import Badge from '../ui/Badge'
import Button from '../ui/Button'
import { Card } from '../ui/Card'
import MonoText from '../ui/MonoText'
import Reveal from '../ui/Reveal'

const SHOWN = 5

export interface Props {
  issue: Issue
  captureName: string
  /** Called with the addresses of an affected flow when it is clicked, to filter to it. */
  onFilterTo: (endpoints: Affected['endpoints']) => void
}

function Field({ label, testId, children }: { label: string; testId: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[5rem_1fr] sm:gap-4">
      <dt className="text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="min-w-0 whitespace-pre-wrap break-words text-theme-sm text-gray-700 dark:text-gray-300" data-testid={testId}>
        {children}
      </dd>
    </div>
  )
}

/**
 * One issue as an actionable card: its severity, title and count; what is
 * wrong, how much it touches and what to do about it; the Wireshark filter in
 * a code block with buttons to copy it or a tshark command that lists the
 * first matching packets; and, on request, the affected flows and the events
 * behind an aggregated issue.
 */
export default memo(function IssueCard({ issue, captureName, onFilterTo }: Props) {
  const [details, setDetails] = useState(false)
  const [showAll, setShowAll] = useState(false)
  const toast = useToast()
  const affected = affectedOf(issue)
  const shown = showAll ? affected : affected.slice(0, SHOWN)
  const occurrences = issue.occurrences ?? []
  const filter = issue.wireshark_filter
  const count = Math.max(issue.count ?? 1, 1)
  const hasDetails = affected.length > 0 || occurrences.length > 0

  const copy = async (text: string, done: string) => {
    if (await copyText(text)) toast.show(done)
    else toast.show('Could not copy. Select the text and copy it by hand.', 'error')
  }

  return (
    <Card data-testid="issue-card" className="overflow-hidden transition-shadow duration-200 hover:shadow-theme-md">
      <div className="space-y-4 p-6 sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
          <h3 className="text-base font-semibold text-gray-800 dark:text-white/90" data-testid="issue-card-title">
            {issue.title}
          </h3>
          {count > 1 && (
            <span className="rounded-full bg-gray-100 dark:bg-gray-800 px-2 py-1 text-theme-xs font-medium text-gray-600 dark:text-gray-400" data-testid="issue-card-count">
              ×{count}
            </span>
          )}
          {(issue.protocols ?? []).map((p) => (
            <span key={p} className={`rounded px-2 py-1 text-[11px] font-medium ${protocolColor(p).badge}`}>
              {p}
            </span>
          ))}
        </div>

        <dl className="space-y-3">
          <Field label="What" testId="issue-card-description">
            <MonoText>{issue.description}</MonoText>
          </Field>
          <Field label="Impact" testId="issue-impact">
            {impactOf(issue)}
          </Field>
          <Field label="Fix" testId="issue-fix">
            {issue.recommendation ? <MonoText>{issue.recommendation}</MonoText> : 'No specific fix is known for this kind of issue. Check the packets with the Wireshark filter below.'}
          </Field>
        </dl>

        {filter ? (
          <div data-testid="wireshark-filter-block">
            <p className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Wireshark filter</p>
            <pre className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-900 dark:bg-black/40 p-3 text-theme-sm text-gray-100">
              <code data-testid="wireshark-filter" className="whitespace-pre-wrap break-all font-mono">
                {filter}
              </code>
            </pre>
          </div>
        ) : (
          <p className="text-theme-sm text-gray-500 dark:text-gray-400" data-testid="no-wireshark-filter">
            There is no Wireshark filter for this kind of issue.
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {filter && (
            <>
              <Button size="sm" className="px-3 py-2 text-xs" data-testid="copy-filter" onClick={() => copy(filter, 'Filter copied to clipboard')}>
                Copy Filter
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="px-3 py-2 text-xs"
                data-testid="copy-tshark-command"
                title={`Copies a tshark command that lists the first ${count} matching ${count === 1 ? 'packet' : 'packets'}`}
                onClick={() => copy(tsharkCommand(captureName, filter, count), 'tshark command copied to clipboard')}
              >
                Show {count.toLocaleString()} {count === 1 ? 'packet' : 'packets'}
              </Button>
            </>
          )}
          {hasDetails && (
            <Button variant="outline" size="sm" className="px-3 py-2 text-xs" aria-expanded={details} data-testid="issue-details-toggle" onClick={() => setDetails((v) => !v)}>
              {details ? 'Hide Details' : 'View Details'}
            </Button>
          )}
        </div>

        <Reveal show={details} testId="issue-details-panel">
          <div className="space-y-4 pt-1">
            {affected.length > 0 && (
              <div data-testid="affected">
                <p className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Affected</p>
                <ul className="flex flex-wrap gap-2">
                  {shown.map((a) => (
                    <li key={a.label}>
                      {a.endpoints.length > 0 ? (
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
                  ))}
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
            {occurrences.length > 0 && <OccurrenceTable issue={issue} occurrences={occurrences} />}
          </div>
        </Reveal>
      </div>
    </Card>
  )
})
