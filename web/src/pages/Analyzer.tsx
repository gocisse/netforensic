import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ApiError, SessionExpiredError } from '../api'
import { useAuth } from '../auth/useAuth'
import CaptureAlerts from '../components/analyzer/CaptureAlerts'
import AnalyzeProgress from '../components/analyzer/AnalyzeProgress'
import type { Progress } from '../components/analyzer/analysisSteps'
import UploadCard from '../components/analyzer/UploadCard'
import { AnalysisSkeleton } from '../components/ui/Skeleton'
import { Card } from '../components/ui/Card'
import { isCaptureFile } from '../format'
import type { EmptyResult } from '../types'

/** The answer for a capture with nothing to analyze: no score, just why. */
function NothingToAnalyze({ result }: { result: EmptyResult }) {
  return (
    <div className="space-y-4" data-testid="nothing-to-analyze">
      <h2 className="truncate text-lg font-semibold text-gray-800 dark:text-white/90" title={result.file_name}>
        {result.file_name}
      </h2>
      <CaptureAlerts issues={result.issues} />
      <Card>
        <div className="px-6 py-8 text-center">
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
  const navigate = useNavigate()
  const { search } = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [empty, setEmpty] = useState<EmptyResult | null>(null)
  const [progress, setProgress] = useState<Progress>({ loaded: 0, total: 0, stage: '' })
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
    setProgress({ loaded: 0, total: file.size, stage: '' })
    try {
      const r = await api.analyzeCapture(file, {
        signal: controller.signal,
        onUpload: (loaded, total) => setProgress((p) => ({ ...p, loaded, total })),
        onStage: (stage) => setProgress((p) => ({ ...p, stage })),
      })
      if ('empty' in r) {
        setEmpty(r.empty)
        return
      }
      // The analysis page loads it, in chunks, from the server that holds it.
      navigate({ pathname: `/analysis/${r.analysisId}`, search })
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
        <>
          <AnalyzeProgress progress={progress} />
          <AnalysisSkeleton />
        </>
      )}
      {!isLoading && empty && <NothingToAnalyze result={empty} />}
      {!isLoading && !empty && (
        <Card>
          <div aria-live="polite" className="px-6 py-8 text-center">
            <p className="text-base font-medium text-gray-800 dark:text-white/90">Upload a capture to begin analysis</p>
            <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">The health score, root cause and issues will appear here, with a page for each protocol.</p>
          </div>
        </Card>
      )}
    </>
  )
}
