import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { AnalysisCacheContext } from './context'
import type { CachedAnalysis } from './context'

/** Holds the current analysis for the pages that show it. */
export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<CachedAnalysis | null>(null)
  const value = useMemo(() => ({ current, setCurrent }), [current])
  return <AnalysisCacheContext.Provider value={value}>{children}</AnalysisCacheContext.Provider>
}
