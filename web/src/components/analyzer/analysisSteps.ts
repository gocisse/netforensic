import { formatBytes } from '../../format'

/** The steps of an analysis, in order. The ids are the stages the server reports. */
export const ANALYSIS_STEPS = [
  { id: 'reading', label: 'Reading packets' },
  { id: 'classifying', label: 'Classifying flows' },
  { id: 'detecting', label: 'Detecting issues' },
  { id: 'reporting', label: 'Generating report' },
] as const

/** What the upload and the analysis have done so far. */
export interface Progress {
  /** Bytes sent, and the size of the file. */
  loaded: number
  total: number
  /** The step the server is on, or '' while the file is still going up. */
  stage: string
}

/** Formats a transfer speed, for example "4.2 MB/s". */
export function formatSpeed(bytesPerSecond: number): string {
  return `${formatBytes(Math.round(bytesPerSecond))}/s`
}
