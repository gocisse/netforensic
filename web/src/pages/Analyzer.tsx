import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ApiError, SessionExpiredError } from '../api'
import { useAnalysisCache } from '../analysis/useAnalysisCache'
import { useAuth } from '../auth/useAuth'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import UploadCard from '../components/analyzer/UploadCard'
import { Card } from '../components/ui/Card'
import { isCaptureFile } from '../format'
import type { ApiResult, EmptyResult } from '../types'
import { isEmptyResult } from '../types'

/** The answer for a capture with nothing to analyze: no score, just why. */
function NothingToAnalyze({ result }: { result: EmptyResult }) {
  return (
    <div className="space-y-4" data-testid="nothing-to-analyze">
      <h2 className="truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name}>
        {result.file_name}
      </h2>
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

/**
 * The dashboard: upload a capture. When the analysis is ready the page moves
 * to it (/analysis/:id); a capture with nothing to analyze is explained here.
 */
export default function Analyzer() {
  const { api } = useAuth()
  const cache = useAnalysisCache()
  const navigate = useNavigate()
  const { search } = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [empty, setEmpty] = useState<ApiResult | null>(null)
  const inFlight = useRef<AbortController | null>(null)

  // Abandon a running upload if the page goes away.
  useEffect(() => () => inFlight.current?.abort(), [])

  const handleSelect = (selected: File | null) => {
    setEmpty(null)
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
    setEmpty(null)
    try {
      const r = await api.analyzeCapture(file, controller.signal)
      if (isEmptyResult(r) || !r.analysis_id) {
        setEmpty(r)
        return
      }
      cache.setCurrent({ id: r.analysis_id, result: r })
      navigate({ pathname: `/analysis/${r.analysis_id}`, search })
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
        <h1 className="text-title-sm font-semibold text-gray-800 dark:text-white/90">Analyzer</h1>
        <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">Upload a packet capture to find out what went wrong on the network.</p>
      </div>
      <UploadCard file={file} loading={isLoading} error={error} onSelect={handleSelect} onAnalyze={handleAnalyze} />
      {isLoading && (
        <Card>
          <p aria-live="polite" className="px-6 py-12 text-center text-theme-sm text-gray-600 dark:text-gray-400">
            Analyzing capture…
          </p>
        </Card>
      )}
      {!isLoading && empty && isEmptyResult(empty) && <NothingToAnalyze result={empty} />}
      {!isLoading && !empty && (
        <Card>
          <div aria-live="polite" className="px-6 py-12 text-center">
            <p className="text-base font-medium text-gray-800 dark:text-white/90">Upload a capture to begin analysis</p>
            <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">The health score, root cause and issues will appear here, with a page for each protocol.</p>
          </div>
        </Card>
      )}
    </>
  )
}
