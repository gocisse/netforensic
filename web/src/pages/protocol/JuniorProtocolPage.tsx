import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useAnalysisView } from '../../analysis/view'
import JuniorIssueList from '../../components/junior/JuniorIssueList'
import { involvesProtocol } from '../../protocols'
import type { ProtocolPageInfo } from '../../protocols'

/** A protocol page in plain language: the same problems, explained, without filters or technical detail. */
export default function JuniorProtocolPage({ info }: { info: ProtocolPageInfo }) {
  const { id, reportable } = useAnalysisView()
  const issues = useMemo(() => reportable.filter((i) => involvesProtocol(i, info.protocol)), [reportable, info.protocol])
  return (
    <div className="space-y-6" data-testid="junior-protocol-page">
      <Link to={`/analysis/${id}`} className="text-theme-sm font-medium text-brand-600 hover:text-brand-700 dark:text-brand-400">
        Back to the overview
      </Link>
      <JuniorIssueList issues={issues} heading="Related problems" emptyIsNeutral emptyText="No problems of this kind were found." />
    </div>
  )
}
