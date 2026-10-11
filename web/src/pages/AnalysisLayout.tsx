import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, Outlet, useLocation, useParams } from 'react-router-dom'
import { ApiError, SessionExpiredError } from '../api'
import { useAnalysisCache } from '../analysis/useAnalysisCache'
import type { AnalysisView } from '../analysis/view'
import { useAuth } from '../auth/useAuth'
import ProtocolNav from '../components/ProtocolNav'
import Alert from '../components/ui/Alert'
import { Card } from '../components/ui/Card'
import { toParams } from '../filters/model'
import { useFilters } from '../filters/useFilters'
import { isCaptureNote } from '../format'
import { PROTOCOL_PAGES, involvesProtocol } from '../protocols'
import type { AnalysisResult } from '../types'
import { isEmptyResult } from '../types'
import { saveBlob } from '../download'

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
  const { search } = useLocation()

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
  const handleExport = useCallback(async () => {
    if (!result?.analysis_id || exporting) return
    setExporting(true)
    setExportError(null)
    try {
      const { blob, filename } = await api.exportCsv(result.analysis_id, toParams(applied))
      saveBlob(blob, filename)
    } catch (err) {
      if (err instanceof SessionExpiredError) return
      setExportError(err instanceof ApiError ? err.message : 'The export failed.')
    } finally {
      setExporting(false)
    }
  }, [api, result, applied, exporting])

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
        <Link to={{ pathname: '/', search }} className="inline-block text-theme-sm font-medium text-brand-500 hover:text-brand-600">
          Analyze a capture
        </Link>
      </div>
    )
  }
  if (!result || !view) {
    return (
      <Card>
        <p aria-live="polite" className="px-6 py-12 text-center text-theme-sm text-gray-600 dark:text-gray-400">
          Loading the analysis…
        </p>
      </Card>
    )
  }

  return (
    <div className="space-y-5" data-testid="analysis">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="min-w-0 truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name} data-testid="analysis-file-name">
          {result.file_name}
        </h2>
        <Link to="/" data-testid="analyze-another" className="text-theme-sm font-medium text-brand-500 hover:text-brand-600 dark:hover:text-brand-400">
          Analyze another capture
        </Link>
      </div>
      <ProtocolNav id={id} counts={counts} search={search} />
      <Outlet context={view} />
    </div>
  )
}
