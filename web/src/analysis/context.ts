import { createContext } from 'react'
import type { AnalysisResult } from '../types'

/** The analysis the page last uploaded or opened, kept so that moving to its page does not fetch it again. */
export interface CachedAnalysis {
  id: string
  result: AnalysisResult
}

export interface AnalysisCache {
  current: CachedAnalysis | null
  setCurrent: (a: CachedAnalysis | null) => void
}

export const AnalysisCacheContext = createContext<AnalysisCache | null>(null)
