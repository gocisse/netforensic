import { useOutletContext } from 'react-router-dom'
import type { Filters } from '../filters/useFilters'
import type { AnalysisResult, Flow, Issue } from '../types'

/** What the analysis pages share: the analysis, the filters, and what is derived from them. */
export interface AnalysisView {
  id: string
  result: AnalysisResult
  filters: Filters
  /** Every flow of the capture. */
  flows: Flow[]
  /** The issues about the traffic: capture notes left out. */
  reportable: Issue[]
  /** Every issue has arrived: until then `reportable` is the issues so far, and counts made from it are partial. */
  issuesLoaded: boolean
  /** Every flow has arrived: until then `flows` is empty. */
  flowsLoaded: boolean
  /** The number of issues about the traffic, from the server's first chunk, so that it is right before the issues are all there. */
  reportableTotal: number
  /** The name of the capture file, for the Wireshark commands. */
  captureName: string
  onExport: () => void
  exporting: boolean
  exportError: string | null
}

/** The analysis shown by the page the router is on. */
export function useAnalysisView(): AnalysisView {
  return useOutletContext<AnalysisView>()
}
