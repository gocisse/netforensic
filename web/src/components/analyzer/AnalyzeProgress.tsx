import { useEffect, useState } from 'react'
import { formatBytes } from '../../format'
import type { Progress } from './analysisSteps'
import { Card } from '../ui/Card'
import { ANALYSIS_STEPS, formatSpeed } from './analysisSteps'

/**
 * Shows an upload and then the analysis: a bar with "size sent of total" and
 * the upload speed, then "Analyzing…" with the four steps, the current one
 * highlighted and the finished ones checked.
 */
export default function AnalyzeProgress({ progress }: { progress: Progress }) {
  const [startedAt] = useState(() => performance.now())
  const [now, setNow] = useState(() => performance.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(performance.now()), 250)
    return () => window.clearInterval(id)
  }, [])

  const uploading = progress.stage === ''
  const pct = progress.total > 0 ? Math.min(100, Math.round((progress.loaded / progress.total) * 100)) : 0
  const seconds = Math.max(0.001, (now - startedAt) / 1000)
  const current = ANALYSIS_STEPS.findIndex((s) => s.id === progress.stage)

  return (
    <Card data-testid="analyze-progress">
      <div className="space-y-6 p-4 sm:p-6" aria-live="polite">
        <div>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <p className="text-theme-sm font-medium text-gray-800 dark:text-white/90">{uploading ? 'Uploading…' : 'Uploaded'}</p>
            <p className="font-mono text-theme-xs text-gray-600 dark:text-gray-400" data-testid="upload-stats">
              {formatBytes(progress.loaded)} of {formatBytes(progress.total)}
              {uploading && progress.loaded > 0 && <> · {formatSpeed(progress.loaded / seconds)}</>}
            </p>
          </div>
          <div
            role="progressbar"
            aria-label="Upload progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={pct}
            data-testid="upload-bar"
            className="mt-2 h-2 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-800"
          >
            <div className="h-full rounded-full bg-brand-500 transition-[width] duration-200 ease-out" style={{ width: `${pct}%` }} />
          </div>
        </div>

        <div>
          <p className="text-theme-sm font-medium text-gray-800 dark:text-white/90" data-testid="analyzing-label">
            {uploading ? 'Waiting for the upload…' : 'Analyzing…'}
          </p>
          <ol className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-2" data-testid="analysis-steps" aria-label="Analysis steps">
            {ANALYSIS_STEPS.map((step, i) => {
              const state = uploading ? 'pending' : i < current ? 'done' : i === current ? 'active' : 'pending'
              return (
                <li key={step.id} className="flex items-center gap-2" data-testid="analysis-step" data-step={step.id} data-state={state} aria-current={state === 'active' ? 'step' : undefined}>
                  <span
                    className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-theme-sm font-medium ${
                      state === 'active'
                        ? 'bg-brand-50 dark:bg-brand-500/15 text-brand-700 dark:text-brand-400'
                        : state === 'done'
                          ? 'bg-success-50 dark:bg-success-500/15 text-success-700 dark:text-success-400'
                          : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'
                    }`}
                  >
                    {state === 'done' ? (
                      <span aria-hidden="true">✓</span>
                    ) : state === 'active' ? (
                      <span aria-hidden="true" className="h-2 w-2 animate-pulse rounded-full bg-brand-500" />
                    ) : null}
                    {step.label}
                  </span>
                  {i < ANALYSIS_STEPS.length - 1 && (
                    <span aria-hidden="true" className="text-gray-500 dark:text-gray-400">
                      →
                    </span>
                  )}
                </li>
              )
            })}
          </ol>
        </div>
      </div>
    </Card>
  )
}
