import { useEffect, useRef, useState } from 'react'
import { ApiError, SessionExpiredError } from '../api'
import { useAuth } from '../auth/useAuth'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import HealthCard from '../components/analyzer/HealthCard'
import IssuesTable from '../components/analyzer/IssuesTable'
import UploadCard from '../components/analyzer/UploadCard'
import FlowTable from '../components/FlowTable'
import ProtocolDistribution from '../components/ProtocolDistribution'
import { Card, CardHeader } from '../components/ui/Card'
import StatCard from '../components/ui/StatCard'
import { flowMatches, isCaptureFile, isCaptureNote, issueMatches, PROTOCOL_FILTERS } from '../format'
import { ClockIcon, FlowsIcon, PacketsIcon } from '../icons'
import type { AnalysisResult, ApiResult, EmptyResult } from '../types'
import { isEmptyResult } from '../types'

/** The result of an analysis: the health score, composition, issues, flows and advice. */
function Report({ result }: { result: AnalysisResult }) {
  const d = result.diagnosis
  const [protocol, setProtocol] = useState<string>('All')

  const reportable = result.issues.filter((i) => !isCaptureNote(i))
  const issues = reportable.filter((i) => issueMatches(i, protocol))
  const stats = result.protocol_stats ?? []
  const stat = stats.find((p) => p.protocol === protocol)
  const busiest = protocol === 'All' ? (result.top_talkers ?? []) : (stat?.top_flows ?? [])
  const slowest = (result.slow_flows ?? []).filter((f) => flowMatches(f, protocol))

  return (
    <div className="space-y-6" data-testid="report">
      <CaptureAlerts issues={result.issues} />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HealthCard diagnosis={d} />
        <StatCard
          label="Packets"
          value={result.total_packets.toLocaleString()}
          hint={
            <span className="inline-flex items-center gap-1.5">
              <ClockIcon className="h-4 w-4" />
              over {result.duration}
            </span>
          }
          icon={<PacketsIcon className="h-6 w-6" />}
          iconTone="bg-brand-50 text-brand-500"
        />
        <StatCard
          label="Flows"
          value={result.total_flows.toLocaleString()}
          hint={`${reportable.length.toLocaleString()} ${reportable.length === 1 ? 'issue' : 'issues'} found`}
          icon={<FlowsIcon className="h-6 w-6" />}
          iconTone="bg-blue-light-50 text-blue-light-500"
        />
      </div>

      <ProtocolDistribution stats={stats} selected={protocol} onSelect={setProtocol} />

      <Card>
        <CardHeader
          title="Top issues"
          description={
            protocol !== 'All' ? (
              <span data-testid="filter-summary">
                Showing {issues.length.toLocaleString()} of {reportable.length.toLocaleString()} issues involving {protocol}
              </span>
            ) : undefined
          }
          action={
            <label className="flex items-center gap-2 text-theme-sm font-medium text-gray-700">
              Protocol filter
              <select
                data-testid="protocol-filter"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="h-10 rounded-lg border border-gray-300 bg-white px-3 text-theme-sm shadow-theme-xs focus:border-brand-300 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
              >
                {PROTOCOL_FILTERS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </label>
          }
        />
        <div className="border-t border-gray-100 p-2 sm:p-3">
          <IssuesTable key={protocol} issues={issues} filter={protocol} />
        </div>
      </Card>

      <FlowTable
        testId="busiest-flows"
        title={protocol === 'All' ? 'Busiest flows' : `Busiest ${protocol} flows`}
        flows={busiest}
        emptyMessage={`No ${protocol} flows were found in this capture.`}
      />
      <FlowTable
        testId="slowest-flows"
        title={protocol === 'All' ? 'Slowest flows' : `Slowest ${protocol} flows`}
        flows={slowest}
        emptyMessage={
          protocol === 'All'
            ? 'No flows with measurable timing metrics.'
            : `None of the slowest flows in this capture are ${protocol}.`
        }
      />

      {d.recommendations.length > 0 && (
        <Card>
          <CardHeader title="Recommendations" />
          <ol className="list-decimal space-y-2 border-t border-gray-100 p-5 pl-10 text-theme-sm text-gray-600 sm:p-6 sm:pl-11">
            {d.recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ol>
        </Card>
      )}
    </div>
  )
}

/** The answer for a capture with nothing to analyze: no score, just why. */
function NothingToAnalyze({ result }: { result: EmptyResult }) {
  return (
    <div className="space-y-4" data-testid="nothing-to-analyze">
      <CaptureAlerts issues={result.issues} />
      <Card>
        <div className="px-6 py-10 text-center">
          <p className="text-base font-medium text-gray-800">{result.message}</p>
          <p className="mt-1 text-theme-sm text-gray-500">There is nothing to score, so no health score is shown.</p>
        </div>
      </Card>
    </div>
  )
}

function ResultsArea({ loading, result }: { loading: boolean; result: ApiResult | null }) {
  if (loading) {
    return (
      <Card>
        <p aria-live="polite" className="px-6 py-12 text-center text-theme-sm text-gray-600">
          Analyzing capture…
        </p>
      </Card>
    )
  }
  if (!result) {
    return (
      <Card>
        <div aria-live="polite" className="px-6 py-12 text-center">
          <p className="text-base font-medium text-gray-800">Upload a capture to begin analysis</p>
          <p className="mt-1 text-theme-sm text-gray-500">The health score, root cause and issues will appear here.</p>
        </div>
      </Card>
    )
  }
  return (
    <div className="space-y-4" aria-live="polite">
      <h2 className="truncate text-lg font-semibold text-gray-800" title={result.file_name}>
        {result.file_name}
      </h2>
      {isEmptyResult(result) ? <NothingToAnalyze result={result} /> : <Report key={result.analysis_time} result={result} />}
    </div>
  )
}

/** The analyzer page: upload a capture, then read the analysis. */
export default function Analyzer() {
  const { api } = useAuth()
  const [file, setFile] = useState<File | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ApiResult | null>(null)
  const inFlight = useRef<AbortController | null>(null)

  // Abandon a running upload if the page goes away.
  useEffect(() => () => inFlight.current?.abort(), [])

  const handleSelect = (selected: File | null) => {
    setResult(null)
    if (selected && !isCaptureFile(selected)) {
      setFile(null)
      setError(`"${selected.name}" is not a capture file. Choose a .pcap or .pcapng file.`)
      return
    }
    setError(null)
    setFile(selected)
  }

  const handleAnalyze = async () => {
    if (!file || isLoading) return
    const controller = new AbortController()
    inFlight.current = controller
    setIsLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await api.analyzeCapture(file, controller.signal))
    } catch (err) {
      if (controller.signal.aborted || err instanceof SessionExpiredError) return // signed out: the sign-in page explains
      setError(err instanceof ApiError ? err.message : 'Something went wrong while analyzing the capture.')
    } finally {
      if (inFlight.current === controller) {
        inFlight.current = null
        setIsLoading(false)
      }
    }
  }

  return (
    <>
      <div>
        <h1 className="text-title-sm font-semibold text-gray-800">Analyzer</h1>
        <p className="mt-1 text-theme-sm text-gray-500">Upload a packet capture to find out what went wrong on the network.</p>
      </div>
      <UploadCard file={file} loading={isLoading} error={error} onSelect={handleSelect} onAnalyze={handleAnalyze} />
      <ResultsArea loading={isLoading} result={result} />
    </>
  )
}
