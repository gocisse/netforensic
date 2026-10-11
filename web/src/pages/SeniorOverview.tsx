import { useMemo } from 'react'
import { useAnalysisView } from '../analysis/view'
import ActiveFilters from '../components/ActiveFilters'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import HealthCard from '../components/analyzer/HealthCard'
import IssuesTable from '../components/analyzer/IssuesTable'
import FilterPanel from '../components/FilterPanel'
import FlowTable from '../components/FlowTable'
import ProtocolDistribution from '../components/ProtocolDistribution'
import TopTalkers from '../components/TopTalkers'
import { Card, CardHeader } from '../components/ui/Card'
import StatCard from '../components/ui/StatCard'
import { flowBytes, matchFlow, matchIssue, protocolStats, topTalkers, worstTiming } from '../filters/match'
import { ClockIcon, FlowsIcon, PacketsIcon } from '../icons'

/** How many flows the flow tables list. */
const FLOWS_SHOWN = 10

/** The overview of an analysis: the verdict, the filters, the composition, the issues and the flows. */
export default function SeniorOverview() {
  const { result, filters, flows: allFlows, reportable, captureName, onExport, exporting, exportError } = useAnalysisView()
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

  const exportDisabledReason = result.analysis_id ? undefined : 'The server did not keep this analysis, so it cannot export it. Analyze the capture again.'
  const sourceIsTalker = talkers.some((t) => t.ip === applied.sourceIp)

  return (
    <div className="space-y-6" data-testid="report">
      <CaptureAlerts issues={result.issues} />

      {/* The verdict stays in view while the details below scroll (from the lg breakpoint, where there is room). */}
      <div className="z-30 -mx-4 bg-gray-50 px-4 pb-1 pt-1 dark:bg-gray-950 md:-mx-6 md:px-6 lg:sticky lg:top-[65px]" data-testid="sticky-health">
        <HealthCard diagnosis={d} />
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          label="Packets"
          value={result.total_packets.toLocaleString()}
          hint={
            <span className="inline-flex items-center gap-2">
              <ClockIcon className="h-4 w-4" />
              over {result.duration}
            </span>
          }
          icon={<PacketsIcon className="h-6 w-6" />}
          iconTone="bg-brand-50 dark:bg-brand-500/15 text-brand-600 dark:text-brand-400"
        />
        <StatCard
          label="Flows"
          value={result.total_flows.toLocaleString()}
          hint={`${reportable.length.toLocaleString()} ${reportable.length === 1 ? 'issue' : 'issues'} found`}
          icon={<FlowsIcon className="h-6 w-6" />}
          iconTone="bg-blue-light-50 dark:bg-blue-light-500/15 text-blue-light-500"
        />
        <StatCard
          label="Shown after filters"
          data-testid="shown-card"
          value={`${issues.length.toLocaleString()} / ${flows.length.toLocaleString()}`}
          hint="issues / flows"
          iconTone="bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white/90"
        />
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

      <TopTalkers talkers={talkers} selected={sourceIsTalker ? applied.sourceIp : ''} onSelect={(ip) => filters.set({ sourceIp: ip })} />

      <ProtocolDistribution stats={stats} selected={applied.protocol} onSelect={(p) => filters.set({ protocol: p })} filtered={filters.active} />

      <Card>
        <CardHeader
          title="Top issues"
          description={
            <span data-testid="filter-summary">
              Showing {issues.length.toLocaleString()} of {reportable.length.toLocaleString()} {reportable.length === 1 ? 'issue' : 'issues'}
            </span>
          }
        />
        <div className="border-t border-gray-100 dark:border-gray-800 p-2 sm:p-3">
          <IssuesTable key={JSON.stringify(applied)} issues={issues} filtered={filters.active} onClearFilters={filters.reset} captureName={captureName} />
        </div>
      </Card>

      <p className="text-theme-sm font-medium text-gray-600 dark:text-gray-400" data-testid="flow-summary">
        Showing {flows.length.toLocaleString()} of {result.total_flows.toLocaleString()} {result.total_flows === 1 ? 'flow' : 'flows'}
        {flows.length > FLOWS_SHOWN && <span className="font-normal text-gray-500 dark:text-gray-400"> (the {FLOWS_SHOWN} busiest and slowest are listed)</span>}
      </p>
      <FlowTable
        testId="busiest-flows"
        title={applied.protocol === 'All' ? 'Busiest flows' : `Busiest ${applied.protocol} flows`}
        flows={busiest}
        filtered={filters.active}
        onClearFilters={filters.reset}
        emptyMessage={filters.active ? 'No flows match your filters.' : 'No flows were found in this capture.'}
      />
      <FlowTable
        testId="slowest-flows"
        title={applied.protocol === 'All' ? 'Slowest flows' : `Slowest ${applied.protocol} flows`}
        flows={slowest}
        filtered={filters.active}
        onClearFilters={filters.reset}
        emptyMessage={filters.active ? 'None of the flows that match your filters have measurable timing metrics.' : 'No flows with measurable timing metrics.'}
      />

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
    </div>
  )
}

