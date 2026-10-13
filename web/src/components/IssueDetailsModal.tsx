import { useCallback, useState } from 'react'
import { copyText } from '../clipboard'
import { protocolColor, severityColor } from '../format'
import { impactOf } from '../issueView'
import { useToast } from '../toast/useToast'
import type { Issue } from '../types'
import { affectedOf, tsharkCommand } from '../wireshark'
import type { Affected } from '../wireshark'
import Modal from './Modal'
import OccurrenceTable from './OccurrenceTable'
import Badge from './ui/Badge'
import Button from './ui/Button'
import MonoText from './ui/MonoText'

/** How many affected flows are listed before the rest is behind a button. */
const SHOWN = 10

export interface Props {
  issue: Issue
  captureName: string
  onClose: () => void
  /** Called with the addresses of an affected flow when it is clicked, to filter the page to it. */
  onFilterTo: (endpoints: Affected['endpoints']) => void
}

function Section({ label, testId, children }: { label: string; testId: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{label}</h3>
      <div className="min-w-0 whitespace-pre-wrap break-words text-theme-sm text-gray-700 dark:text-gray-300" data-testid={testId}>
        {children}
      </div>
    </section>
  )
}

/**
 * Everything about one issue in a dialog: its severity, title, count and
 * protocol; what is wrong, how much it touches and what to do about it; the
 * addresses involved (click one to filter the page to it); the Wireshark
 * filter in a code block; and buttons to copy the filter or a tshark command,
 * to copy a command that lists the first matching packets, and to open the
 * events behind an aggregated issue.
 */
export default function IssueDetailsModal({ issue, captureName, onClose, onFilterTo }: Props) {
  const toast = useToast()
  const [showAll, setShowAll] = useState(false)
  const [events, setEvents] = useState(false)
  const affected = affectedOf(issue)
  const shown = showAll ? affected : affected.slice(0, SHOWN)
  const occurrences = issue.occurrences ?? []
  const filter = issue.wireshark_filter
  const count = Math.max(issue.count ?? 1, 1)

  const copy = useCallback(
    async (text: string, done: string) => {
      if (await copyText(text)) toast.show(done)
      else toast.show('Could not copy. Select the text and copy it by hand.', 'error')
    },
    [toast],
  )
  const filterTo = (eps: Affected['endpoints']) => {
    onFilterTo(eps)
    onClose()
  }

  return (
    <Modal title="Issue details" onClose={onClose} wide>
      <div className="mt-4 space-y-6" data-testid="issue-details">
        <div className="flex flex-wrap items-center gap-2" data-testid="issue-details-header">
          <Badge color={severityColor(issue.severity)}>{issue.severity}</Badge>
          <h3 className="text-base font-semibold text-gray-800 dark:text-white/90" data-testid="issue-details-title">
            {issue.title}
          </h3>
          {count > 1 && (
            <span className="rounded-full bg-gray-100 dark:bg-gray-800 px-2 py-1 text-theme-xs font-medium text-gray-600 dark:text-gray-400" data-testid="issue-details-count">
              ×{count.toLocaleString()}
            </span>
          )}
          {(issue.protocols ?? []).map((p) => (
            <span key={p} className={`rounded px-2 py-1 text-[11px] font-medium ${protocolColor(p).badge}`}>
              {p}
            </span>
          ))}
        </div>

        <Section label="What" testId="issue-card-description">
          <MonoText>{issue.description}</MonoText>
        </Section>
        <Section label="Impact" testId="issue-impact">
          {impactOf(issue)}
        </Section>

        {affected.length > 0 && (
          <section data-testid="affected">
            <h3 className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Affected IPs</h3>
            <ul className="flex flex-wrap gap-2">
              {shown.map((a) => (
                <li key={a.label} className="max-w-full">
                  {a.endpoints.length > 0 ? (
                    <button
                      type="button"
                      data-testid="affected-flow"
                      onClick={() => filterTo(a.endpoints)}
                      title="Filter the page to this flow"
                      className="max-w-full truncate rounded-lg border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60 px-3 py-1 font-mono text-theme-xs text-gray-800 dark:text-white/90 hover:border-brand-500 hover:text-brand-700 dark:hover:text-brand-300"
                    >
                      {a.label}
                    </button>
                  ) : (
                    <span data-testid="affected-name" className="inline-block max-w-full truncate rounded-lg bg-gray-50 dark:bg-gray-800/60 px-3 py-1 font-mono text-theme-xs text-gray-700 dark:text-gray-300" title={a.label}>
                      {a.label}
                    </span>
                  )}
                </li>
              ))}
              {affected.length > SHOWN && (
                <li>
                  <button type="button" onClick={() => setShowAll((v) => !v)} className="px-2 py-1 text-theme-xs font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700">
                    {showAll ? 'Show fewer' : `+${(affected.length - SHOWN).toLocaleString()} more`}
                  </button>
                </li>
              )}
            </ul>
          </section>
        )}

        <Section label="Fix" testId="issue-fix">
          {issue.recommendation ? <MonoText>{issue.recommendation}</MonoText> : 'No specific fix is known for this kind of issue. Check the packets with the Wireshark filter below.'}
        </Section>

        {filter ? (
          <section data-testid="wireshark-filter-block">
            <h3 className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Wireshark filter</h3>
            <pre className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-900 dark:bg-black/40 p-3 text-theme-sm text-gray-100">
              <code data-testid="wireshark-filter" className="whitespace-pre-wrap break-all font-mono">
                {filter}
              </code>
            </pre>
          </section>
        ) : (
          <p className="text-theme-sm text-gray-500 dark:text-gray-400" data-testid="no-wireshark-filter">
            There is no Wireshark filter for this kind of issue.
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2" data-testid="issue-actions">
          {filter && (
            <>
              <Button size="sm" className="px-3 py-2 text-xs" data-testid="copy-filter" onClick={() => copy(filter, 'Filter copied to clipboard')}>
                Copy Filter
              </Button>
              <Button variant="outline" size="sm" className="px-3 py-2 text-xs" data-testid="copy-tshark-full" onClick={() => copy(tsharkCommand(captureName, filter), 'tshark command copied to clipboard')}>
                Copy tshark command
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
          {occurrences.length > 0 && (
            <Button variant="outline" size="sm" className="px-3 py-2 text-xs" aria-expanded={events} data-testid="issue-occurrences-toggle" onClick={() => setEvents((v) => !v)}>
              {events ? 'Hide occurrences' : `View occurrences (${occurrences.length.toLocaleString()})`}
            </Button>
          )}
        </div>

        {events && occurrences.length > 0 && (
          <div data-testid="issue-occurrences">
            <OccurrenceTable issue={issue} occurrences={occurrences} />
          </div>
        )}
      </div>
    </Modal>
  )
}
