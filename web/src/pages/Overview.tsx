import { useCallback, useMemo, useState } from 'react'
import { useAnalysisView } from '../analysis/view'
import ActiveFilters from '../components/ActiveFilters'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import HealthCard from '../components/analyzer/HealthCard'
import IssueGroups from '../components/analyzer/IssueGroups'
import FilterPanel from '../components/FilterPanel'
import FlowDetailsModal from '../components/FlowDetailsModal'
import FlowTable from '../components/FlowTable'
import ProtocolDistribution from '../components/ProtocolDistribution'
import TopTalkers from '../components/TopTalkers'
import { Card, CardHeader } from '../components/ui/Card'
import { TableSkeleton } from '../components/ui/Skeleton'
import { displayIP } from '../filters/ip'
import { problemFlows } from '../flowTimeline'
import type { Flow } from '../types'
import type { Affected } from '../wireshark'
import { flowBytes, matchFlow, matchIssue, protocolStats, topTalkers, worstTiming } from '../filters/match'

/** How many flows the flow tables list. */
const FLOWS_SHOWN = 10
/** How many flows with issues the Bad Traffic tab lists. */
const PROBLEM_FLOWS_SHOWN = 25

/** The Bad Traffic tab: the verdict, the filters, the composition, the issues grouped by severity and the flows. */
export default function Overview() {
  const { result, filters, flows: allFlows, reportable, reportableTotal, issuesLoaded, flowsLoaded, captureName, onExport, exporting, exportError } = useAnalysisView()
  const d = result.diagnosis
  const { parsed, applied } = filters

  const issues = useMemo(() => reportable.filter((i) => matchIssue(parsed, i)), [reportable, parsed])
  const flows = useMemo(() => allFlows.filter((f) => matchFlow(parsed, f)), [allFlows, parsed])
  const stats = useMemo(() => (allFlows.length > 0 ? protocolStats(flows) : (result.protocol_stats ?? [])), [allFlows, flows, result])

  // What the filter panel offers comes from the whole capture, not from what is left.
  const protocols = useMemo(() => {
    const names = (allFlows.length > 0 ? protocolStats(allFlows) : (result.protocol_stats ?? [])).map((s) => s.protocol)
    return applied.protocol !== 'All' && !names.includes(applied.protocol) ? [...names, applied.protocol] : names
  }, [allFlows, result, applied.protocol])
  const categories = useMemo(() => {
    const counts = new Map<string, number>()
    for (const i of reportable) counts.set(i.category, (counts.get(i.category) ?? 0) + 1)
    for (const c of applied.categories) if (!counts.has(c)) counts.set(c, 0)
    return [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name))
  }, [reportable, applied.categories])
  const severities = useMemo(() => [...new Set(reportable.map((i) => i.severity))], [reportable])
  const talkers = useMemo(() => topTalkers(allFlows, 5), [allFlows])

  const busiest = useMemo(() => [...flows].sort((a, b) => flowBytes(b) - flowBytes(a)).slice(0, FLOWS_SHOWN), [flows])
  const slowest = useMemo(
    () =>
      flows
        .filter((f) => worstTiming(f) > 0)
        .sort((a, b) => worstTiming(b) - worstTiming(a))
        .slice(0, FLOWS_SHOWN),
    [flows],
  )

  const troubled = useMemo(() => problemFlows(flows, PROBLEM_FLOWS_SHOWN), [flows])
  const troubledTotal = useMemo(() => flows.filter((f) => (f.issue_count ?? 0) > 0).length, [flows])
  const [selected, setSelected] = useState<Flow | null>(null)
  const closeFlow = useCallback(() => setSelected(null), [])

  const exportDisabledReason = result.analysis_id ? undefined : 'The server did not keep this analysis, so it cannot export it. Analyze the capture again.'
  const { set: setFilters } = filters
  const filterTo = useCallback(
    (eps: Affected['endpoints']) => {
      if (eps.length === 0) return
      setFilters({ sourceIp: displayIP(eps[0].ip), destIp: eps.length > 1 ? displayIP(eps[1].ip) : '' })
    },
    [setFilters],
  )
  const sourceIsTalker = talkers.some((t) => t.ip === applied.sourceIp)

  return (
    <div className="space-y-6" data-testid="report">
      <CaptureAlerts issues={result.issues} />

      {/* The verdict stays in view while the details below scroll (from the lg breakpoint, where there is room). */}
      <div className="z-30 -mx-4 bg-gray-50 px-4 pb-1 pt-1 dark:bg-gray-950 md:-mx-6 md:px-6 lg:sticky lg:top-[65px]" data-testid="sticky-health">
        <HealthCard diagnosis={d} />
      </div>

      <FilterPanel
        filters={filters}
        protocols={protocols}
        categories={categories}
        severities={severities}
        onExport={onExport}
        exporting={exporting}
        exportDisabledReason={exportDisabledReason}
        exportError={exportError}
      />
      <ActiveFilters filters={filters} />

      {flowsLoaded ? (
        <TopTalkers talkers={talkers} selected={sourceIsTalker ? applied.sourceIp : ''} onSelect={(ip) => filters.set({ sourceIp: ip })} />
      ) : (
        <TableSkeleton title="Top talkers" rows={3} testId="skeleton-talkers" />
      )}

      <ProtocolDistribution stats={stats} selected={applied.protocol} onSelect={(p) => filters.set({ protocol: p })} filtered={filters.active} />

      <section className="space-y-4" data-testid="bad-traffic-issues">
        <h2 className="text-lg font-semibold text-gray-800 dark:text-white/90">Issues</h2>
        <p className="text-theme-sm font-medium text-gray-600 dark:text-gray-400" data-testid="filter-summary">
          Showing {issues.length.toLocaleString()} of {reportableTotal.toLocaleString()} {reportableTotal === 1 ? 'issue' : 'issues'}
          {!issuesLoaded && <span className="font-normal text-gray-500 dark:text-gray-400"> (still loading)</span>}
        </p>
        <IssueGroups issues={issues} filtered={filters.active} onClearFilters={filters.reset} captureName={captureName} onFilterTo={filterTo} loading={!issuesLoaded} />
      </section>

      {flowsLoaded ? (
        <>
        <FlowTable
          testId="problem-flows"
          title={troubledTotal > troubled.length ? `Flows with issues (${troubled.length} of ${troubledTotal.toLocaleString()} shown)` : 'Flows with issues'}
          flows={troubled}
          onSelect={setSelected}
          filtered={filters.active}
          onClearFilters={filters.reset}
          emptyMessage={filters.active ? 'None of the flows that match your filters has an issue.' : 'No flow has an issue. Open the Good Traffic tab to see them all.'}
        />

        <p className="text-theme-sm font-medium text-gray-600 dark:text-gray-400" data-testid="flow-summary">
          Showing {flows.length.toLocaleString()} of {result.total_flows.toLocaleString()} {result.total_flows === 1 ? 'flow' : 'flows'}
          {flows.length > FLOWS_SHOWN && <span className="font-normal text-gray-500 dark:text-gray-400"> (the {FLOWS_SHOWN} busiest and slowest are listed)</span>}
        </p>
        <FlowTable
          testId="busiest-flows"
          title={applied.protocol === 'All' ? 'Busiest flows' : `Busiest ${applied.protocol} flows`}
          flows={busiest}
          onSelect={setSelected}
          filtered={filters.active}
          onClearFilters={filters.reset}
          emptyMessage={filters.active ? 'No flows match your filters.' : 'No flows were found in this capture.'}
        />
        <FlowTable
          testId="slowest-flows"
          title={applied.protocol === 'All' ? 'Slowest flows' : `Slowest ${applied.protocol} flows`}
          flows={slowest}
          onSelect={setSelected}
          filtered={filters.active}
          onClearFilters={filters.reset}
          emptyMessage={filters.active ? 'None of the flows that match your filters have measurable timing metrics.' : 'No flows with measurable timing metrics.'}
        />
        </>
      ) : (
        <>
          <TableSkeleton title="Flows with issues" rows={3} testId="skeleton-problem-flows" />
          <TableSkeleton title="Busiest flows" rows={3} testId="skeleton-flows" />
        </>
      )}

      {d.recommendations.length > 0 && (
        <Card>
          <CardHeader title="Recommendations" />
          <ol className="list-decimal space-y-2 border-t border-gray-100 dark:border-gray-800 p-6 pl-8 text-theme-sm text-gray-600 dark:text-gray-400 sm:p-6 sm:pl-8">
            {d.recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ol>
        </Card>
      )}
      {selected && <FlowDetailsModal flow={selected} issues={reportable} captureName={captureName} onClose={closeFlow} onFilterTo={filterTo} />}
    </div>
  )
}

