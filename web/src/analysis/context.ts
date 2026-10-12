import { createContext } from 'react'
import type { AnalysisResult, LoadProgress } from '../types'

/**
 * The analysis the page last opened, as far as it has arrived: its verdict
 * first, then the issues and the flows. Kept so that moving between its pages
 * does not fetch it again.
 */
export interface CachedAnalysis {
  id: string
  result: AnalysisResult
  /** Every issue has arrived (result.issues is complete). */
  issuesDone: boolean
  /** Every flow has arrived (result.flows and result.healthy_flows are complete). */
  flowsDone: boolean
}

/** Why an analysis could not be loaded. */
export interface LoadError {
  id: string
  message: string
  /** The server no longer has it. */
  gone: boolean
}

export interface AnalysisCache {
  current: CachedAnalysis | null
  error: LoadError | null
  /** Starts loading the analysis with this ID (a no-op if it is the one loading or loaded). */
  load: (id: string) => void
}

export const AnalysisCacheContext = createContext<AnalysisCache | null>(null)

/** How far the lists have arrived, or null when everything has. It changes often, so it has its own context. */
export const LoadProgressContext = createContext<LoadProgress | null>(null)
