import { useContext } from 'react'
import { AnalysisCacheContext } from './context'
import type { AnalysisCache } from './context'

/** The cache of the current analysis. */
export function useAnalysisCache(): AnalysisCache {
  const cache = useContext(AnalysisCacheContext)
  if (!cache) throw new Error('useAnalysisCache must be used inside <AnalysisProvider>')
  return cache
}
