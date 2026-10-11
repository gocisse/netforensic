import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAnalysisView } from '../../analysis/view'
import ActiveFilters from '../../components/ActiveFilters'
import IssueCard from '../../components/analyzer/IssueCard'
import Button from '../../components/ui/Button'
import { Card } from '../../components/ui/Card'
import { displayIP } from '../../filters/ip'
import { matchIssue } from '../../filters/match'
import { SEVERITIES } from '../../filters/model'
import { severityRank } from '../../format'
import { involvesProtocol } from '../../protocols'
import type { ProtocolPageInfo } from '../../protocols'
import type { Issue } from '../../types'
import type { Affected } from '../../wireshark'

/** Whether an issue mentions the text anywhere a person would look for it. */
function matchesSearch(issue: Issue, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (needle === '') return true
  const hay = [issue.title, issue.description, issue.flow_id, issue.target, issue.domain, issue.category, ...(issue.occurrences ?? []).map((o) => o.subject)]
  return hay.some((h) => h?.toLowerCase().includes(needle))
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'text-error-700 dark:text-error-400',
  ERROR: 'text-error-600 dark:text-error-400',
  WARNING: 'text-warning-600 dark:text-warning-400',
  INFO: 'text-blue-light-600 dark:text-blue-light-400',
}

/**
 * The page of one protocol: every issue that involves it, in full, with the
 * Wireshark filter to check it. Severity and the text search narrow the list;
 * the IP and port filters of the overview apply here too, and a click on an
 * affected flow filters to it.
 */
export default function SeniorProtocolPage({ info }: { info: ProtocolPageInfo }) {
  const { reportable, filters, captureName } = useAnalysisView()
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''

  const forProtocol = useMemo(() => reportable.filter((i) => involvesProtocol(i, info.protocol)), [reportable, info.protocol])
  // this page is about one protocol, so the protocol filter of the overview does not apply
  const parsed = useMemo(() => ({ ...filters.parsed, protocol: '' }), [filters.parsed])
  const issues = useMemo(
    () =>
      forProtocol
        .filter((i) => matchIssue(parsed, i) && matchesSearch(i, q))
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.count ?? 1) - (a.count ?? 1) || a.title.localeCompare(b.title)),
    [forProtocol, parsed, q],
  )
  const severities = SEVERITIES.filter((s) => s !== 'CRITICAL' || forProtocol.some((i) => i.severity === 'CRITICAL'))
  const narrowed = filters.active || q.trim() !== ''

  const setQ = (value: string) => {
    const out = new URLSearchParams(window.location.search) // the address bar is always current; see useFilters
    if (value === '') out.delete('q')
    else out.set('q', value)
    setParams(out, { replace: true })
  }
  const toggleSeverity = (s: string) =>
    filters.set({ severities: filters.applied.severities.includes(s) ? filters.applied.severities.filter((x) => x !== s) : [...filters.applied.severities, s] })
  const filterTo = (eps: Affected['endpoints']) => {
    if (eps.length === 0) return
    filters.set({ sourceIp: displayIP(eps[0].ip), destIp: eps.length > 1 ? displayIP(eps[1].ip) : '' })
  }

  return (
    <div className="space-y-5" data-testid="protocol-page" data-protocol={info.protocol}>
      <div>
        <h2 className="text-xl font-semibold text-gray-800 dark:text-white/90">{info.title}</h2>
        <p className="mt-1 max-w-3xl text-theme-sm text-gray-500 dark:text-gray-400">{info.blurb}</p>
      </div>

      <Card>
        <div className="flex flex-wrap items-end gap-x-6 gap-y-4 p-4 sm:p-5">
          <fieldset>
            <legend className="mb-1.5 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Severity</legend>
            <div className="flex flex-wrap gap-2">
              {severities.map((s) => {
                const on = filters.applied.severities.includes(s)
                return (
                  <label
                    key={s}
                    className={`inline-flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-1.5 text-theme-sm ${on ? 'border-brand-500 bg-brand-25 dark:bg-brand-500/10' : 'border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/60'}`}
                  >
                    <input type="checkbox" checked={on} onChange={() => toggleSeverity(s)} data-testid={`page-severity-${s}`} className="h-4 w-4 rounded border-gray-300 accent-brand-500" />
                    <span className={`font-medium ${SEVERITY_STYLE[s]}`}>{s}</span>
                  </label>
                )
              })}
            </div>
          </fieldset>
          <div className="min-w-56 flex-1">
            <label htmlFor="protocol-search" className="mb-1.5 block text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
              Search flows and issues
            </label>
            <input
              id="protocol-search"
              data-testid="protocol-search"
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="An address, a port, a domain or a word"
              autoComplete="off"
              spellCheck={false}
              className="h-10 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-transparent dark:bg-gray-900 px-3 text-sm text-gray-800 dark:text-white/90 placeholder:text-gray-400 focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
            />
          </div>
          <p className="text-theme-sm font-medium text-gray-600 dark:text-gray-400" data-testid="protocol-count">
            Showing {issues.length.toLocaleString()} of {forProtocol.length.toLocaleString()} {info.protocol} {forProtocol.length === 1 ? 'issue' : 'issues'}
          </p>
        </div>
      </Card>
      <ActiveFilters filters={filters} omit={['proto']} />

      {forProtocol.length === 0 ? (
        <Card>
          <div className="px-6 py-10 text-center" data-testid="protocol-empty">
            <p className="text-base font-medium text-gray-800 dark:text-white/90">No {info.protocol} issues were found in this capture</p>
            <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">Either the traffic is healthy or the capture holds no {info.protocol} traffic. The overview shows what it does hold.</p>
          </div>
        </Card>
      ) : issues.length === 0 ? (
        <Card>
          <div className="px-6 py-10 text-center" data-testid="protocol-no-match">
            <p className="text-base font-medium text-gray-800 dark:text-white/90">No {info.protocol} issues match your filters</p>
            <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">Remove a filter, or clear them all to see every {info.protocol} issue again.</p>
            {narrowed && (
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={() => {
                  filters.reset()
                  setQ('')
                }}
              >
                Clear filters
              </Button>
            )}
          </div>
        </Card>
      ) : (
        <div className="space-y-4">
          {issues.map((issue) => (
            <IssueCard key={issue.id} issue={issue} captureName={captureName} onFilterTo={filterTo} />
          ))}
        </div>
      )}
    </div>
  )
}
