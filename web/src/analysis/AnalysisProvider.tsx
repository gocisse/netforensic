import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { ApiError, SessionExpiredError } from '../api'
import { useAuth } from '../auth/useAuth'
import type { LoadProgress } from '../types'
import { AnalysisCacheContext, LoadProgressContext } from './context'
import type { CachedAnalysis, LoadError } from './context'
import { AnalysisAssembler } from './stream'

/** How often the progress counters are updated while chunks stream in (ms). */
const PROGRESS_EVERY = 100
/** The issues are handed to the page when this many have arrived, then each time the count doubles: the page works the whole list out every time. */
const FIRST_ISSUE_PUBLISH = 300

/**
 * Loads the analysis a page asks for, in chunks, and holds it: the verdict is
 * shown the moment the first chunk is in, the issues are handed over a few
 * times as they grow, the flows once they are all there.
 */
export function AnalysisProvider({ children }: { children: ReactNode }) {
  const { api } = useAuth()
  const [current, setCurrent] = useState<CachedAnalysis | null>(null)
  const [error, setError] = useState<LoadError | null>(null)
  const [progress, setProgress] = useState<LoadProgress | null>(null)
  const running = useRef<{ id: string; controller: AbortController } | null>(null)

  useEffect(() => () => running.current?.controller.abort(), [])

  const load = useCallback(
    (id: string) => {
      if (running.current?.id === id) return // already loading, or loaded
      running.current?.controller.abort()
      const controller = new AbortController()
      running.current = { id, controller }
      setCurrent(null)
      setError(null)
      setProgress(null)

      const asm = new AnalysisAssembler()
      let nextIssuePublish = FIRST_ISSUE_PUBLISH
      let timer: ReturnType<typeof setTimeout> | undefined
      const publish = () => {
        const result = asm.snapshot()
        if (result) setCurrent({ id, result, issuesDone: asm.issuesDone, flowsDone: asm.flowsDone })
      }
      const tick = () => {
        timer = undefined
        setProgress(asm.issuesDone && asm.flowsDone ? null : asm.progress())
      }
      const scheduleTick = () => {
        if (timer === undefined) timer = setTimeout(tick, PROGRESS_EVERY)
      }

      api
        .streamAnalysis(
          id,
          (ev) => {
            switch (asm.apply(ev)) {
              case 'summary':
                publish()
                tick()
                break
              case 'overview':
                publish()
                break
              case 'issues':
                scheduleTick()
                if (asm.issuesDone || asm.issuesLoaded >= nextIssuePublish) {
                  nextIssuePublish = Math.max(nextIssuePublish, asm.issuesLoaded) * 2
                  publish()
                }
                break
              case 'flows':
                scheduleTick()
                if (asm.flowsDone) publish()
                break
              case 'done':
                clearTimeout(timer)
                timer = undefined
                publish()
                setProgress(null)
                break
            }
          },
          controller.signal,
        )
        .catch((err) => {
          clearTimeout(timer)
          if (controller.signal.aborted || err instanceof SessionExpiredError) return
          if (running.current?.id === id) running.current = null // let it be tried again
          setProgress(null)
          setError({
            id,
            message: err instanceof ApiError ? err.message : 'The analysis could not be loaded.',
            gone: err instanceof ApiError && err.status === 404,
          })
        })
    },
    [api],
  )

  const cache = useMemo(() => ({ current, error, load }), [current, error, load])
  return (
    <AnalysisCacheContext.Provider value={cache}>
      <LoadProgressContext.Provider value={progress}>{children}</LoadProgressContext.Provider>
    </AnalysisCacheContext.Provider>
  )
}
