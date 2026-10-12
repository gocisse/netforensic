import type { AnalysisResult, ChunkCounts, Diagnosis, Flow, Issue, LoadProgress, ProtocolStat } from '../types.ts'

/** The first chunk: the verdict and how much is coming. */
export interface SummaryData {
  file_name: string
  total_packets: number
  total_flows: number
  analysis_time: string
  duration: string
  diagnosis: Diagnosis
  analysis_id: string
  good_traffic_filter: string
  counts: ChunkCounts
}

/** The second chunk: what the overview shows before the flows are there. */
export interface OverviewData {
  protocol_stats: ProtocolStat[]
  top_talkers: Flow[]
  slow_flows: Flow[]
}

/** One line of the chunked answer of GET /api/analysis/{id}?chunked=1. */
export type ChunkEvent =
  | { chunk: 'summary'; data: SummaryData }
  | { chunk: 'overview'; data: OverviewData }
  | { chunk: 'issues'; offset: number; data: Issue[] }
  | { chunk: 'flows'; offset: number; data: Flow[] }
  | { chunk: 'done' }

/**
 * Splits streamed text into complete lines. `carry` is the unfinished line
 * left over from the text before; the returned `carry` is what is left over
 * now. Blank lines are dropped.
 */
export function parseLines(carry: string, text: string): { lines: string[]; carry: string } {
  const all = (carry + text).split('\n')
  const rest = all.pop() ?? ''
  return { lines: all.filter((l) => l.trim() !== ''), carry: rest }
}

/**
 * Puts an analysis together from its chunks. The lists grow as batches come;
 * `snapshot` gives the analysis as far as it has arrived. The flows are given
 * out only when all of them are there: the page works them out in one piece
 * (the busiest, the protocols, the healthy ones), and doing that again for
 * every batch of a hundred thousand flows would cost far more than waiting.
 */
export class AnalysisAssembler {
  private head: AnalysisResult | null = null
  private issues: Issue[] = []
  private flows: Flow[] = []
  private finished = false

  /** Folds one chunk in and returns which kind it was. */
  apply(ev: ChunkEvent): ChunkEvent['chunk'] {
    switch (ev.chunk) {
      case 'summary': {
        const d = ev.data
        this.head = {
          file_name: d.file_name,
          total_packets: d.total_packets,
          total_flows: d.total_flows,
          analysis_time: d.analysis_time,
          duration: d.duration,
          diagnosis: d.diagnosis,
          analysis_id: d.analysis_id,
          good_traffic_filter: d.good_traffic_filter,
          counts: d.counts,
          issues: [],
          top_talkers: [],
          slow_flows: [],
          protocol_stats: [],
        }
        break
      }
      case 'overview':
        if (this.head) {
          this.head.protocol_stats = ev.data.protocol_stats
          this.head.top_talkers = ev.data.top_talkers
          this.head.slow_flows = ev.data.slow_flows
        }
        break
      case 'issues':
        for (const i of ev.data) this.issues.push(i)
        break
      case 'flows':
        for (const f of ev.data) this.flows.push(f)
        break
      case 'done':
        this.finished = true
        break
    }
    return ev.chunk
  }

  /** Whether the summary has arrived. */
  get started(): boolean {
    return this.head !== null
  }

  get issuesLoaded(): number {
    return this.issues.length
  }

  /** Whether every issue has arrived. */
  get issuesDone(): boolean {
    return this.head !== null && (this.finished || this.issues.length >= this.head.counts!.issues)
  }

  /** Whether every flow has arrived. */
  get flowsDone(): boolean {
    return this.head !== null && (this.finished || this.flows.length >= this.head.counts!.flows)
  }

  progress(): LoadProgress {
    const c = this.head?.counts
    return { issues: { loaded: this.issues.length, total: c?.issues ?? 0 }, flows: { loaded: this.flows.length, total: c?.flows ?? 0 } }
  }

  /** The analysis as far as it has arrived, or null before the summary. */
  snapshot(): AnalysisResult | null {
    if (!this.head) return null
    const flowsDone = this.flowsDone
    return {
      ...this.head,
      issues: this.issuesDone ? this.issues : this.issues.slice(),
      flows: flowsDone ? this.flows : [],
      healthy_flows: flowsDone ? this.flows.filter((f) => !f.issue_count) : [],
    }
  }
}
