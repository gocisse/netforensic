import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, Outlet, useLocation, useParams } from 'react-router-dom'
import { ApiError, SessionExpiredError } from '../api'
import { useAnalysisCache } from '../analysis/useAnalysisCache'
import type { AnalysisView } from '../analysis/view'
import { useAuth } from '../auth/useAuth'
import LoadProgressBar from '../components/analyzer/LoadProgressBar'
import ProtocolNav from '../components/ProtocolNav'
import ScrollToTop from '../components/ScrollToTop'
import SummaryBar from '../components/SummaryBar'
import TrafficTabs from '../components/TrafficTabs'
import Alert from '../components/ui/Alert'
import { AnalysisSkeleton } from '../components/ui/Skeleton'
import { toParams } from '../filters/model'
import { useFilters } from '../filters/useFilters'
import { isCaptureNote } from '../format'
import { PROTOCOL_PAGES, involvesProtocol } from '../protocols'
import { worthShowing } from '../topology/model'
import { saveBlob } from '../download'
import { isTyping } from '../shortcuts/isTyping'
import { useToast } from '../toast/useToast'

/**
 * The frame of an analysis (/analysis/:id): the file name, a summary, the
 * Bad Traffic / Good Traffic tabs, beneath Bad Traffic the tabs of the
 * protocols, and the page the router picks. It asks the analysis provider
 * for the analysis, which streams it in from the server (the verdict first,
 * then the issues and the flows) or already has it; the filters live here, so
 * they follow the user from tab to tab.
 */
export default function AnalysisLayout() {
  const { id = '' } = useParams()
  const { api } = useAuth()
  const cache = useAnalysisCache()
  const filters = useFilters()
  const { search, pathname } = useLocation()
  const toast = useToast()

  const { load } = cache
  useEffect(() => load(id), [id, load])
  const loaded = cache.current?.id === id ? cache.current : null
  const result = loaded?.result ?? null
  const issuesLoaded = loaded?.issuesDone ?? false
  const flowsLoaded = loaded?.flowsDone ?? false
  const failed = cache.error?.id === id ? cache.error : null
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const flows = useMemo(() => result?.flows ?? [], [result])
  const reportable = useMemo(() => (result ? result.issues.filter((i) => !isCaptureNote(i)) : []), [result])
  const reportableTotal = result?.counts?.reportable_issues ?? reportable.length
  // The numbers on the protocol tabs are counted from the issues, so they wait until all are there.
  const counts = useMemo(() => {
    if (!issuesLoaded) return undefined
    const out: Record<string, number> = {}
    for (const p of PROTOCOL_PAGES) out[p.protocol] = reportable.filter((i) => involvesProtocol(i, p.protocol)).length
    return out
  }, [reportable, issuesLoaded])

  // The diagram is offered when the capture has issues, or one address carries much of the traffic.
  const showTopology = useMemo(() => worthShowing(reportableTotal, flows), [reportableTotal, flows])

  const { applied } = filters

  // Escape clears the filters, unless it is meant for a dialog or for the field being typed in.
  const { active: filtersActive, reset: resetFilters } = filters
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented || !filtersActive) return
      if (document.querySelector('[role="dialog"]')) return
      if (isTyping(e.target)) {
        ;(e.target as HTMLElement).blur()
        return
      }
      resetFilters()
      toast.show('Filters cleared', 'info')
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [filtersActive, resetFilters, toast])
  const handleExport = useCallback(async () => {
    if (!result?.analysis_id || exporting) return
    setExporting(true)
    setExportError(null)
    toast.show('Export started', 'info')
    try {
      const { blob, filename } = await api.exportCsv(result.analysis_id, toParams(applied))
      saveBlob(blob, filename)
      toast.show('Export complete')
    } catch (err) {
      if (err instanceof SessionExpiredError) return
      const message = err instanceof ApiError ? err.message : 'The export failed.'
      setExportError(message)
      toast.show(message, 'error')
    } finally {
      setExporting(false)
    }
  }, [api, result, applied, exporting, toast])

  const view = useMemo<AnalysisView | null>(
    () =>
      result
        ? { id, result, filters, flows, reportable, issuesLoaded, flowsLoaded, reportableTotal, captureName: result.file_name, onExport: handleExport, exporting, exportError }
        : null,
    [id, result, filters, flows, reportable, issuesLoaded, flowsLoaded, reportableTotal, handleExport, exporting, exportError],
  )

  if (failed && !result) {
    return (
      <div className="space-y-4" data-testid="analysis-unavailable">
        <Alert variant={failed.gone ? 'info' : 'error'} role={failed.gone ? 'status' : 'alert'}>
          {failed.gone ? 'That analysis is no longer on the server (it keeps the latest few for two hours, and forgets them when it restarts). Upload the capture again.' : failed.message}
        </Alert>
        <Link to={{ pathname: '/', search }} className="inline-block text-theme-sm font-medium text-brand-600 dark:text-brand-400 hover:text-brand-600">
          Analyze a capture
        </Link>
      </div>
    )
  }
  if (!result || !view) return <AnalysisSkeleton />

  return (
    <div className="space-y-6" data-testid="analysis" data-loaded={issuesLoaded && flowsLoaded ? 'true' : 'false'}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="min-w-0 truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name} data-testid="analysis-file-name">
          {result.file_name}
        </h2>
        <Link to="/" data-testid="analyze-another" className="text-theme-sm font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">
          Analyze another capture
        </Link>
      </div>
      <SummaryBar result={result} issues={reportableTotal} />
      <LoadProgressBar />
      <TrafficTabs id={id} issues={reportableTotal} goodFlows={result.counts?.healthy_flows ?? (result.healthy_flows ?? []).length} search={search} />
      {!pathname.replace(/\/$/, '').endsWith('/good') && <ProtocolNav id={id} counts={counts} search={search} topology={showTopology} />}
      {/* keyed by the page, so that a change of tab fades the new page in */}
      <div key={pathname} className="animate-fade-in" data-testid="page-transition">
        <Outlet context={view} />
      </div>
      <ScrollToTop />
    </div>
  )
}
