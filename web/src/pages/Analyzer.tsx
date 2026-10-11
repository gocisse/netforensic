import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ApiError, SessionExpiredError } from '../api'
import { useAuth } from '../auth/useAuth'
import ActiveFilters from '../components/ActiveFilters'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import HealthCard from '../components/analyzer/HealthCard'
import IssuesTable from '../components/analyzer/IssuesTable'
import UploadCard from '../components/analyzer/UploadCard'
import FilterPanel from '../components/FilterPanel'
import FlowTable from '../components/FlowTable'
import ProtocolDistribution from '../components/ProtocolDistribution'
import TopTalkers from '../components/TopTalkers'
import Alert from '../components/ui/Alert'
import { Card, CardHeader } from '../components/ui/Card'
import StatCard from '../components/ui/StatCard'
import { flowBytes, matchFlow, matchIssue, protocolStats, topTalkers, worstTiming } from '../filters/match'
import { toParams } from '../filters/model'
import type { Filters } from '../filters/useFilters'
import { useFilters } from '../filters/useFilters'
import { readParams, writeParams } from '../filters/urlState'
import { isCaptureFile, isCaptureNote } from '../format'
import { ClockIcon, FlowsIcon, PacketsIcon } from '../icons'
import type { AnalysisResult, ApiResult, EmptyResult } from '../types'
import { isEmptyResult } from '../types'

/** How many flows the flow tables list. */
const FLOWS_SHOWN = 10

interface ReportProps {
  result: AnalysisResult
  filters: Filters
  onExport: () => void
  exporting: boolean
  exportError: string | null
}

/** The result of an analysis: the health score, composition, issues, flows and advice. */
function Report({ result, filters, onExport, exporting, exportError }: ReportProps) {
  const d = result.diagnosis
  const { parsed, applied } = filters

  const allFlows = useMemo(() => result.flows ?? [], [result])
  const reportable = useMemo(() => result.issues.filter((i) => !isCaptureNote(i)), [result])
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
            <span className="inline-flex items-center gap-1.5">
              <ClockIcon className="h-4 w-4" />
              over {result.duration}
            </span>
          }
          icon={<PacketsIcon className="h-6 w-6" />}
          iconTone="bg-brand-50 dark:bg-brand-500/15 text-brand-500"
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
          <IssuesTable key={JSON.stringify(applied)} issues={issues} filtered={filters.active} onClearFilters={filters.reset} />
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
        emptyMessage={filters.active ? 'No flows match your filters.' : 'No flows were found in this capture.'}
      />
      <FlowTable
        testId="slowest-flows"
        title={applied.protocol === 'All' ? 'Slowest flows' : `Slowest ${applied.protocol} flows`}
        flows={slowest}
        emptyMessage={filters.active ? 'None of the flows that match your filters have measurable timing metrics.' : 'No flows with measurable timing metrics.'}
      />

      {d.recommendations.length > 0 && (
        <Card>
          <CardHeader title="Recommendations" />
          <ol className="list-decimal space-y-2 border-t border-gray-100 dark:border-gray-800 p-5 pl-10 text-theme-sm text-gray-600 dark:text-gray-400 sm:p-6 sm:pl-11">
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
          <p className="text-base font-medium text-gray-800 dark:text-white/90">{result.message}</p>
          <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">There is nothing to score, so no health score is shown.</p>
        </div>
      </Card>
    </div>
  )
}

interface ResultsProps {
  loading: boolean
  result: ApiResult | null
  filters: Filters
  onExport: () => void
  exporting: boolean
  exportError: string | null
}

function ResultsArea({ loading, result, filters, onExport, exporting, exportError }: ResultsProps) {
  if (loading) {
    return (
      <Card>
        <p aria-live="polite" className="px-6 py-12 text-center text-theme-sm text-gray-600 dark:text-gray-400">
          Analyzing capture…
        </p>
      </Card>
    )
  }
  if (!result) {
    return (
      <Card>
        <div aria-live="polite" className="px-6 py-12 text-center">
          <p className="text-base font-medium text-gray-800 dark:text-white/90">Upload a capture to begin analysis</p>
          <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">The health score, root cause and issues will appear here.</p>
        </div>
      </Card>
    )
  }
  return (
    <div className="space-y-4" aria-live="polite">
      <h2 className="truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name}>
        {result.file_name}
      </h2>
      {isEmptyResult(result) ? <NothingToAnalyze result={result} /> : <Report key={result.analysis_time} result={result} filters={filters} onExport={onExport} exporting={exporting} exportError={exportError} />}
    </div>
  )
}

/** Saves a downloaded file under the name the server suggested. */
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** The analyzer page: upload a capture, then read the analysis. */
export default function Analyzer() {
  const { api } = useAuth()
  const filters = useFilters()
  const [file, setFile] = useState<File | null>(null)
  // loading from the start if the address names an analysis to reload
  const [isLoading, setIsLoading] = useState(() => readParams().get('a') !== null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [result, setResult] = useState<ApiResult | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const inFlight = useRef<AbortController | null>(null)

  // Abandon a running upload if the page goes away.
  useEffect(() => () => inFlight.current?.abort(), [])

  // A refresh keeps the filters in the address bar, and with them the ID of the
  // analysis, which the server holds for a while: show it again.
  useEffect(() => {
    const id = readParams().get('a')
    if (!id) return
    const controller = new AbortController()
    api
      .getAnalysis(id, controller.signal)
      .then((r) => {
        if (!controller.signal.aborted) setResult(r)
      })
      .catch((err) => {
        if (controller.signal.aborted || err instanceof SessionExpiredError) return
        writeParams({ a: undefined })
        setNotice(err instanceof ApiError && err.status === 404 ? 'The analysis you had open is no longer on the server. Upload the capture again; your filters are kept.' : 'The previous analysis could not be reloaded. Upload the capture again.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setIsLoading(false)
      })
    return () => controller.abort()
  }, [api])

  const handleSelect = (selected: File | null) => {
    setResult(null)
    setNotice(null)
    setExportError(null)
    writeParams({ a: undefined })
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
    setNotice(null)
    setExportError(null)
    setResult(null)
    writeParams({ a: undefined })
    try {
      const r = await api.analyzeCapture(file, controller.signal)
      setResult(r)
      if (!isEmptyResult(r)) writeParams({ a: r.analysis_id })
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

  const analysisId = result && !isEmptyResult(result) ? result.analysis_id : undefined
  const { applied } = filters
  const handleExport = useCallback(async () => {
    if (!analysisId || exporting) return
    setExporting(true)
    setExportError(null)
    try {
      const { blob, filename } = await api.exportCsv(analysisId, toParams(applied))
      saveBlob(blob, filename)
    } catch (err) {
      if (err instanceof SessionExpiredError) return
      setExportError(err instanceof ApiError ? err.message : 'The export failed.')
    } finally {
      setExporting(false)
    }
  }, [api, analysisId, applied, exporting])

  return (
    <>
      <div>
        <h1 className="text-title-sm font-semibold text-gray-800 dark:text-white/90">Analyzer</h1>
        <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">Upload a packet capture to find out what went wrong on the network.</p>
      </div>
      <UploadCard file={file} loading={isLoading} error={error} onSelect={handleSelect} onAnalyze={handleAnalyze} />
      {notice && (
        <div data-testid="reload-notice">
          <Alert variant="info">{notice}</Alert>
        </div>
      )}
      <ResultsArea loading={isLoading} result={result} filters={filters} onExport={handleExport} exporting={exporting} exportError={exportError} />
    </>
  )
}
