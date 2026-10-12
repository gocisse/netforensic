import type { AnalysisResult } from '../types'

/** One line that sums the capture up: "Total: X packets · Y flows · Z issues · Health: N/100". */
export default function SummaryBar({ result, issues }: { result: AnalysisResult; issues: number }) {
  return (
    <p className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 px-4 py-3 text-theme-sm text-gray-700 dark:text-gray-300" data-testid="summary-bar">
      <span className="font-semibold text-gray-800 dark:text-white/90">Total:</span> {result.total_packets.toLocaleString()} {result.total_packets === 1 ? 'packet' : 'packets'} · {result.total_flows.toLocaleString()}{' '}
      {result.total_flows === 1 ? 'flow' : 'flows'} · {issues.toLocaleString()} {issues === 1 ? 'issue' : 'issues'} · <span className="font-semibold text-gray-800 dark:text-white/90">Health:</span>{' '}
      <span data-testid="summary-health">{result.diagnosis.health_score}/100</span>
    </p>
  )
}
