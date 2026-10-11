import { useMemo } from 'react'
import { useAnalysisView } from '../analysis/view'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import JuniorHealthCard from '../components/junior/JuniorHealthCard'
import JuniorFlowTable from '../components/junior/JuniorFlowTable'
import JuniorIssueList from '../components/junior/JuniorIssueList'
import JuniorProtocolDistribution from '../components/junior/JuniorProtocolDistribution'
import { flowBytes } from '../filters/match'
import { useDashboardMode } from '../mode/useDashboardMode'

const STATUS_RANK = { broken: 2, slow: 1, working: 0 } as const

/**
 * The overview in plain language: a traffic light, the problems we found and
 * what to do about them, what the network is used for, and the connections
 * that matter. No filters, scores, packet counts or protocol names.
 */
export default function JuniorOverview() {
  const { result, reportable, flows } = useAnalysisView()
  const { setMode } = useDashboardMode()

  const shownFlows = useMemo(
    () =>
      [...flows]
        .sort((a, b) => STATUS_RANK[b.status ?? 'working'] - STATUS_RANK[a.status ?? 'working'] || flowBytes(b) - flowBytes(a))
        .slice(0, 10),
    [flows],
  )

  return (
    <div className="space-y-6" data-testid="junior-overview">
      <CaptureAlerts issues={result.issues} />
      <JuniorHealthCard diagnosis={result.diagnosis} />
      <JuniorIssueList issues={reportable} heading="What we found" />
      <JuniorProtocolDistribution stats={result.protocol_stats ?? []} />
      <JuniorFlowTable title="Connections to look at" flows={shownFlows} emptyMessage="No connections were found in this recording." />
      <p className="text-theme-sm text-gray-600 dark:text-gray-400">
        Need the technical detail?{' '}
        <button type="button" onClick={() => setMode('senior')} className="font-medium text-brand-600 underline hover:text-brand-700 dark:text-brand-400" data-testid="to-senior">
          Switch to Senior mode
        </button>
        .
      </p>
    </div>
  )
}
