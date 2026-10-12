import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, Outlet, useLocation, useParams } from 'react-router-dom'
import { ApiError, SessionExpiredError } from '../api'
import { useAnalysisCache } from '../analysis/useAnalysisCache'
import type { AnalysisView } from '../analysis/view'
import { useAuth } from '../auth/useAuth'
import ProtocolNav from '../components/ProtocolNav'
import Alert from '../components/ui/Alert'
import { AnalysisSkeleton } from '../components/ui/Skeleton'
import { toParams } from '../filters/model'
import { useFilters } from '../filters/useFilters'
import { isCaptureNote } from '../format'
import { PROTOCOL_PAGES, involvesProtocol } from '../protocols'
import type { AnalysisResult } from '../types'
import { isEmptyResult } from '../types'
import { saveBlob } from '../download'
import { isTyping } from '../shortcuts/isTyping'
import { useToast } from '../toast/useToast'

/**
 * The frame of an analysis (/analysis/:id): the file name, the tabs (the
 * overview and one page per protocol) and the page the router picks. It gets
 * the analysis from the cache if the page just uploaded it, else from the
 * server, which keeps the latest ones; the filters live here, so they follow
 * the user from tab to tab.
 */
export default function AnalysisLayout() {
  const { id = '' } = useParams()
  const { api } = useAuth()
  const cache = useAnalysisCache()
  const filters = useFilters()
  const { search, pathname } = useLocation()
  const toast = useToast()

  const cached = cache.current?.id === id ? cache.current.result : null
  const [fetched, setFetched] = useState<{ id: string; result: AnalysisResult } | null>(null)
  const [failed, setFailed] = useState<{ id: string; message: string; gone: boolean } | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const { setCurrent } = cache
  useEffect(() => {
    if (cached) return
    const controller = new AbortController()
    api
      .getAnalysis(id, controller.signal)
      .then((r) => {
        if (controller.signal.aborted) return
        if (isEmptyResult(r)) {
          setFailed({ id, message: 'That analysis holds nothing to show.', gone: false })
          return
        }
        setFetched({ id, result: r })
        setCurrent({ id, result: r })
      })
      .catch((err) => {
        if (controller.signal.aborted || err instanceof SessionExpiredError) return
        setFailed({
          id,
          message: err instanceof ApiError ? err.message : 'The analysis could not be loaded.',
          gone: err instanceof ApiError && err.status === 404,
        })
      })
    return () => controller.abort()
  }, [api, id, cached, setCurrent])

  const result = cached ?? (fetched?.id === id ? fetched.result : null)

  const flows = useMemo(() => result?.flows ?? [], [result])
  const reportable = useMemo(() => (result ? result.issues.filter((i) => !isCaptureNote(i)) : []), [result])
  const counts = useMemo(() => {
    const out: Record<string, number> = {}
    for (const p of PROTOCOL_PAGES) out[p.protocol] = reportable.filter((i) => involvesProtocol(i, p.protocol)).length
    return out
  }, [reportable])

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
        ? { id, result, filters, flows, reportable, captureName: result.file_name, onExport: handleExport, exporting, exportError }
        : null,
    [id, result, filters, flows, reportable, handleExport, exporting, exportError],
  )

  if (failed && failed.id === id && !result) {
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
    <div className="space-y-6" data-testid="analysis">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="min-w-0 truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name} data-testid="analysis-file-name">
          {result.file_name}
        </h2>
        <Link to="/" data-testid="analyze-another" className="text-theme-sm font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">
          Analyze another capture
        </Link>
      </div>
      <ProtocolNav id={id} counts={counts} search={search} />
      {/* keyed by the page, so that a change of tab fades the new page in */}
      <div key={pathname} className="animate-fade-in" data-testid="page-transition">
        <Outlet context={view} />
      </div>
    </div>
  )
}
