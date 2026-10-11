/** Types for the JSON returned by POST /api/analyze. */

export type Severity = 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO'

/** One event behind an aggregated issue (a flow, a queried domain, ...). */
export interface Occurrence {
  time: string
  subject: string
  value?: number
  unit?: string
}

export interface Issue {
  id: string
  severity: Severity
  category: string
  title: string
  description: string
  timestamp: string
  flow_id?: string
  domain?: string
  target?: string
  /** Number of events folded into this issue. */
  count?: number
  occurrences?: Occurrence[]
}

export interface TimelineEvent {
  timestamp: string
  event_type: string
  description: string
  severity: Severity
}

export interface Diagnosis {
  /** 100 is healthy; badly troubled captures go below 0, down to -50. */
  health_score: number
  primary_cause: string
  confidence: string
  summary: string
  timeline: TimelineEvent[]
  recommendations: string[]
}

/** A full analysis. */
export interface AnalysisResult {
  file_name: string
  total_packets: number
  total_flows: number
  duration: string
  issues: Issue[]
  diagnosis: Diagnosis
}

/** The answer for a capture that holds nothing to analyze. */
export interface EmptyResult {
  file_name: string
  total_packets: 0
  total_flows: 0
  issues: Issue[]
  message: string
}

export type ApiResult = AnalysisResult | EmptyResult

export function isEmptyResult(r: ApiResult): r is EmptyResult {
  return !('diagnosis' in r) || r.diagnosis == null
}
