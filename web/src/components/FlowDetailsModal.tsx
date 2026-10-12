import { useCallback } from 'react'
import { copyText } from '../clipboard'
import { clockTime, firstIssueOf, flowDuration, flowFilter, issuesForFlow, sinceStart } from '../flowTimeline'
import { AlertIcon, CheckCircleIcon, ErrorIcon } from '../icons'
import { useToast } from '../toast/useToast'
import type { Flow, FlowEvent, Issue, Severity } from '../types'
import { tsharkCommand } from '../wireshark'
import type { Affected } from '../wireshark'
import IssueCard from './analyzer/IssueCard'
import { FlowEndpoints } from './FlowTable'
import Modal from './Modal'
import Badge from './ui/Badge'
import Button from './ui/Button'

export interface Props {
  flow: Flow
  /** Every issue of the capture; the ones about this flow are shown. */
  issues: Issue[]
  captureName: string
  onClose: () => void
  /** Called when an affected flow of an issue card is clicked, to filter the page to it. */
  onFilterTo: (endpoints: Affected['endpoints']) => void
}

/** Icon and colors for a timeline event: green for normal, yellow for warnings, red for errors. */
function tone(severity: Severity): { Icon: typeof AlertIcon; text: string; dot: string; name: string } {
  if (severity === 'ERROR' || severity === 'CRITICAL') {
    return { Icon: ErrorIcon, text: 'text-error-600 dark:text-error-400', dot: 'bg-error-50 dark:bg-error-500/15', name: 'error' }
  }
  if (severity === 'WARNING') {
    return { Icon: AlertIcon, text: 'text-warning-600 dark:text-warning-400', dot: 'bg-warning-50 dark:bg-warning-500/15', name: 'warning' }
  }
  return { Icon: CheckCircleIcon, text: 'text-success-600 dark:text-success-400', dot: 'bg-success-50 dark:bg-success-500/15', name: 'normal' }
}

function Stat({ label, testId, children }: { label: string; testId: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">{label}</dt>
      <dd className="mt-1 text-theme-sm font-medium text-gray-800 dark:text-white/90" data-testid={testId}>
        {children}
      </dd>
    </div>
  )
}

function TimelineEvent({ event, start, last }: { event: FlowEvent; start: string; last: boolean }) {
  const t = tone(event.severity)
  const first = event.first_issue === true
  return (
    <li className="relative flex gap-4" data-testid="timeline-event" data-severity={t.name} data-first-issue={first ? 'true' : 'false'}>
      <div className="flex flex-none flex-col items-center">
        <span className={`flex h-8 w-8 flex-none items-center justify-center rounded-full ${t.dot} ${t.text} ${first ? 'ring-2 ring-error-500 ring-offset-2 ring-offset-white dark:ring-offset-gray-900' : ''}`}>
          <t.Icon className="h-4 w-4" />
        </span>
        {!last && <span className="mt-1 w-px flex-1 bg-gray-200 dark:bg-gray-800" aria-hidden="true" />}
      </div>
      <div className={`min-w-0 flex-1 ${last ? '' : 'pb-6'}`}>
        <div className="flex flex-wrap items-center gap-2">
          <time className="font-mono text-theme-xs text-gray-600 dark:text-gray-400" dateTime={event.timestamp} data-testid="timeline-time">
            {clockTime(event.timestamp)}
          </time>
          <span className="text-theme-xs text-gray-500 dark:text-gray-400">{sinceStart(event.timestamp, start)}</span>
          <h4 className="text-theme-sm font-semibold text-gray-800 dark:text-white/90" data-testid="timeline-name">
            {event.event}
          </h4>
          {first && (
            <Badge color="error" variant="solid" className="px-2 py-1">
              First issue
            </Badge>
          )}
        </div>
        <p className="mt-1 break-words text-theme-sm text-gray-600 dark:text-gray-400">{event.description}</p>
      </div>
    </li>
  )
}

/**
 * Everything about one flow in a dialog: which stream it is, the Wireshark
 * filter and tshark command for it, a timeline of what happened with the first
 * problem called out, and the issue cards that are about this flow.
 */
export default function FlowDetailsModal({ flow, issues, captureName, onClose, onFilterTo }: Props) {
  const toast = useToast()
  const filter = flowFilter(flow)
  const timeline = flow.timeline ?? []
  const first = firstIssueOf(flow)
  const flowIssues = issuesForFlow(issues, flow)
  const start = timeline[0]?.timestamp ?? flow.start_time

  const copy = useCallback(
    async (text: string, done: string) => {
      if (await copyText(text)) toast.show(done)
      else toast.show('Could not copy. Select the text and copy it by hand.', 'error')
    },
    [toast],
  )
  const filterTo = useCallback(
    (eps: Affected['endpoints']) => {
      onFilterTo(eps)
      onClose()
    },
    [onFilterTo, onClose],
  )

  return (
    <Modal title="Flow details" onClose={onClose} wide>
      <div className="mt-4 space-y-6" data-testid="flow-details">
        <div className="space-y-4">
          <div className="text-base text-gray-800 dark:text-white/90" data-testid="flow-details-id">
            <FlowEndpoints flow={flow} />
          </div>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="TCP stream" testId="flow-stream">
              {flow.tcp_stream !== undefined ? (
                <span className="rounded-lg bg-brand-50 dark:bg-brand-500/15 px-3 py-1 font-mono text-base font-semibold text-brand-700 dark:text-brand-300">#{flow.tcp_stream}</span>
              ) : (
                <span className="text-gray-500 dark:text-gray-400" title="The stream numbers of this capture could not be worked out reliably; the filter uses addresses and ports">
                  not numbered
                </span>
              )}
            </Stat>
            <Stat label="Packets" testId="flow-packets">
              {flow.packet_count.toLocaleString()}
            </Stat>
            <Stat label="Duration" testId="flow-duration">
              {flowDuration(flow) || '–'}
            </Stat>
            <Stat label="Status" testId="flow-status">
              <Badge color={flow.status === 'broken' ? 'error' : flow.status === 'slow' ? 'warning' : 'success'}>{flow.status ?? 'working'}</Badge>
            </Stat>
          </dl>
        </div>

        <div className="space-y-3">
          <pre className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-900 dark:bg-black/40 p-3 text-theme-sm text-gray-100">
            <code data-testid="flow-filter" className="whitespace-pre-wrap break-all font-mono">
              {filter}
            </code>
          </pre>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" className="px-3 py-2 text-xs" data-testid="copy-flow-filter" onClick={() => copy(filter, 'Filter copied to clipboard')}>
              Copy Wireshark Filter
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="px-3 py-2 text-xs"
              data-testid="copy-flow-tshark"
              onClick={() => copy(tsharkCommand(captureName, filter), 'tshark command copied to clipboard')}
            >
              Copy tshark command
            </Button>
          </div>
        </div>

        {first && (
          <div
            className="flex items-start gap-3 rounded-xl border border-error-200 dark:border-error-500/40 bg-error-25 dark:bg-error-500/10 p-4 text-theme-sm text-gray-800 dark:text-white/90"
            role="status"
            data-testid="first-issue"
          >
            <AlertIcon className="mt-1 h-4 w-4 flex-none text-error-600 dark:text-error-400" />
            <p>
              <strong className="font-semibold">First Issue: {first.event}</strong> at <span className="font-mono">{clockTime(first.timestamp)}</span>
              <span className="text-gray-600 dark:text-gray-400"> ({sinceStart(first.timestamp, start).replace('+', '')} after the first event)</span>
            </p>
          </div>
        )}

        <section aria-labelledby="timeline-heading">
          <h3 id="timeline-heading" className="mb-4 text-base font-semibold text-gray-800 dark:text-white/90">
            Timeline
          </h3>
          {timeline.length > 0 ? (
            <ol data-testid="flow-timeline">
              {timeline.map((e, i) => (
                <TimelineEvent key={`${e.timestamp}-${e.event}-${i}`} event={e} start={start} last={i === timeline.length - 1} />
              ))}
            </ol>
          ) : (
            <p className="text-theme-sm text-gray-600 dark:text-gray-400" data-testid="timeline-empty">
              {flow.protocol === 'TCP'
                ? 'This flow has no problems to put on a timeline.'
                : 'Timelines are built for TCP flows. Use the Wireshark filter above to look at this flow.'}
            </p>
          )}
        </section>

        {flowIssues.length > 0 && (
          <section className="space-y-4" aria-labelledby="flow-issues-heading" data-testid="flow-issues">
            <h3 id="flow-issues-heading" className="text-base font-semibold text-gray-800 dark:text-white/90">
              Issues on this flow
            </h3>
            {flowIssues.map((i) => (
              <IssueCard key={i.id} issue={i} captureName={captureName} onFilterTo={filterTo} />
            ))}
          </section>
        )}
      </div>
    </Modal>
  )
}
