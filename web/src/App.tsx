import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent, DragEvent, ReactNode } from 'react'
import { analyzeCapture, ApiError } from './api'
import { flowMatches, healthTone, issueMatches, NOTE_TITLES, PROTOCOL_FILTERS, severityBadge, sortIssues } from './format'
import FlowTable from './components/FlowTable'
import OccurrenceTable from './components/OccurrenceTable'
import ProtocolDistribution from './components/ProtocolDistribution'
import type { AnalysisResult, ApiResult, EmptyResult, Issue } from './types'
import { isEmptyResult } from './types'

const ACCEPTED_EXTENSIONS = ['.pcap', '.pcapng']

/** Returns true if the file name ends in a supported capture extension. */
function isCaptureFile(file: File): boolean {
  const name = file.name.toLowerCase()
  return ACCEPTED_EXTENSIONS.some((ext) => name.endsWith(ext))
}

/** Formats a byte count for display, for example "4.9 MB". */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function Header() {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-5xl items-center gap-3 px-6 py-4">
        <div
          aria-hidden="true"
          className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600 text-sm font-bold text-white"
        >
          NF
        </div>
        <div>
          <h1 className="text-lg font-semibold leading-tight text-slate-900">
            Netforensic Web Analyzer
          </h1>
          <p className="text-sm text-slate-500">
            Packet capture forensics in your browser
          </p>
        </div>
      </div>
    </header>
  )
}

interface UploadCardProps {
  file: File | null
  loading: boolean
  error: string | null
  onSelect: (file: File | null) => void
  onAnalyze: () => void
}

function UploadCard({ file, loading, error, onSelect, onAnalyze }: UploadCardProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    onSelect(e.target.files?.[0] ?? null)
  }

  const handleDrop = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault()
    setDragging(false)
    if (!loading) onSelect(e.dataTransfer.files?.[0] ?? null)
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="text-base font-semibold text-slate-900">Capture file</h2>
      <p className="mt-1 text-sm text-slate-500">
        Choose a <code className="rounded bg-slate-100 px-1">.pcap</code> or{' '}
        <code className="rounded bg-slate-100 px-1">.pcapng</code> file to analyze.
      </p>

      <label
        htmlFor="capture-file"
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`mt-4 flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
          dragging
            ? 'border-indigo-500 bg-indigo-50'
            : 'border-slate-300 bg-slate-50 hover:border-indigo-400 hover:bg-indigo-50/50'
        } ${loading ? 'pointer-events-none opacity-60' : ''}`}
      >
        {file ? (
          <>
            <span className="text-sm font-medium text-slate-900">{file.name}</span>
            <span className="mt-1 text-xs text-slate-500">{formatSize(file.size)}</span>
            <span className="mt-3 text-xs text-indigo-600">Click or drop to choose a different file</span>
          </>
        ) : (
          <>
            <span className="text-sm font-medium text-slate-700">
              Click to choose a file, or drag one here
            </span>
            <span className="mt-1 text-xs text-slate-500">Accepted: .pcap, .pcapng</span>
          </>
        )}
        <input
          ref={inputRef}
          id="capture-file"
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(',')}
          onChange={handleChange}
          disabled={loading}
          className="sr-only"
        />
      </label>

      {error && (
        <p role="alert" className="mt-3 text-sm text-red-600">
          {error}
        </p>
      )}

      <div className="mt-5 flex items-center justify-end gap-3">
        {file && !loading && (
          <button
            type="button"
            onClick={() => {
              onSelect(null)
              if (inputRef.current) inputRef.current.value = ''
            }}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100"
          >
            Clear
          </button>
        )}
        <button
          type="button"
          onClick={onAnalyze}
          disabled={!file || loading}
          aria-busy={loading}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {loading && (
            <span
              aria-hidden="true"
              className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white"
            />
          )}
          {loading ? 'Analyzing…' : 'Analyze'}
        </button>
      </div>
    </section>
  )
}

const TOP_ISSUES = 10

function HealthScore({ score }: { score: number }) {
  const tone = healthTone(score)
  return (
    <div
      className={`flex h-32 w-32 flex-none flex-col items-center justify-center rounded-full border-4 ${tone.ring} ${tone.bg}`}
      role="img"
      aria-label={`Health score ${score} out of 100, ${tone.label}`}
    >
      <span data-testid="health-score" className={`text-4xl font-bold ${tone.text}`}>
        {score}
      </span>
      <span className={`text-xs font-semibold uppercase tracking-wide ${tone.text}`}>{tone.label}</span>
    </div>
  )
}

function Notice({ tone, children }: { tone: 'warning' | 'info'; children: ReactNode }) {
  const style =
    tone === 'warning'
      ? 'border-yellow-300 bg-yellow-50 text-yellow-900'
      : 'border-sky-200 bg-sky-50 text-sky-900'
  return <div className={`rounded-lg border px-4 py-3 text-sm ${style}`}>{children}</div>
}

/** Banners for problems with the capture file itself. */
function CaptureNotes({ issues }: { issues: Issue[] }) {
  const notes = issues.filter((i) => (NOTE_TITLES as readonly string[]).includes(i.title))
  return (
    <>
      {notes.map((n) => (
        <Notice key={n.id} tone={n.title === 'Truncated Capture' ? 'warning' : 'info'}>
          <span className="font-semibold">{n.title}.</span> {n.description}
        </Notice>
      ))}
    </>
  )
}

/** One issue, with a drill-down into the events behind it if it has any. */
function IssueRow({ issue }: { issue: Issue }) {
  const [open, setOpen] = useState(false)
  const occurrences = issue.occurrences ?? []
  return (
    <li className="px-4 py-3" data-testid="issue-row">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-semibold ${severityBadge(issue.severity)}`}>
          {issue.severity}
        </span>
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">{issue.category}</span>
        <span className="text-sm font-medium text-slate-900">{issue.title}</span>
        {(issue.count ?? 1) > 1 && (
          <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">×{issue.count}</span>
        )}
        {occurrences.length > 0 && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="ml-auto rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-50"
          >
            {open ? 'Hide details' : `View details (${occurrences.length.toLocaleString()})`}
          </button>
        )}
      </div>
      <p className="mt-1 line-clamp-2 text-sm text-slate-500" title={issue.description}>
        {issue.description}
      </p>
      {open && occurrences.length > 0 && <OccurrenceTable issue={issue} occurrences={occurrences} />}
    </li>
  )
}

function IssueList({ issues, filter }: { issues: Issue[]; filter: string }) {
  const [showAll, setShowAll] = useState(false)
  const rows = sortIssues(issues.filter((i) => !(NOTE_TITLES as readonly string[]).includes(i.title)))
  if (rows.length === 0) {
    return (
      <p className="text-sm text-slate-500" data-testid="no-issues">
        {filter === 'All' ? 'No issues were found in this capture.' : `No ${filter} issues were found in this capture.`}
      </p>
    )
  }
  const shown = showAll ? rows : rows.slice(0, TOP_ISSUES)
  return (
    <div>
      <ul className="divide-y divide-slate-100 rounded-lg border border-slate-200">
        {shown.map((issue) => (
          <IssueRow key={issue.id} issue={issue} />
        ))}
      </ul>
      {rows.length > TOP_ISSUES && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="mt-3 text-sm font-medium text-indigo-600 hover:text-indigo-500"
        >
          {showAll ? `Show the top ${TOP_ISSUES} only` : `Show all ${rows.length} issues`}
        </button>
      )}
    </div>
  )
}

function Report({ result }: { result: AnalysisResult }) {
  const d = result.diagnosis
  const [protocol, setProtocol] = useState<string>('All')

  const reportable = result.issues.filter((i) => !(NOTE_TITLES as readonly string[]).includes(i.title))
  const issues = result.issues.filter((i) => issueMatches(i, protocol))
  const shownCount = reportable.filter((i) => issueMatches(i, protocol)).length
  const stats = result.protocol_stats ?? []
  const stat = stats.find((p) => p.protocol === protocol)
  const busiest = protocol === 'All' ? (result.top_talkers ?? []) : (stat?.top_flows ?? [])
  const slowest = (result.slow_flows ?? []).filter((f) => flowMatches(f, protocol))

  return (
    <div className="space-y-6" data-testid="report">
      <CaptureNotes issues={result.issues} />

      <ProtocolDistribution stats={stats} selected={protocol} onSelect={setProtocol} />

      <div className="flex flex-wrap items-center gap-6">
        <HealthScore score={d.health_score} />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Primary cause</p>
          <p data-testid="primary-cause" className="mt-1 text-xl font-semibold text-slate-900">
            {d.primary_cause}
          </p>
          <p className="mt-1 text-sm text-slate-600">
            Confidence: <span className="font-medium">{d.confidence}</span>
          </p>
          <p className="mt-2 text-sm text-slate-600">{d.summary}</p>
        </div>
      </div>

      <dl className="grid grid-cols-3 gap-4 rounded-lg bg-slate-50 p-4 text-center">
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-500">Packets</dt>
          <dd className="text-lg font-semibold">{result.total_packets.toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-500">Flows</dt>
          <dd className="text-lg font-semibold">{result.total_flows.toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-slate-500">Duration</dt>
          <dd className="text-lg font-semibold">{result.duration}</dd>
        </div>
      </dl>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-4">
        <label className="flex items-center gap-2 text-sm font-medium text-slate-700">
          Protocol filter
          <select
            data-testid="protocol-filter"
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className="rounded-md border border-slate-300 bg-white px-2 py-1 text-sm focus:border-indigo-500 focus:outline-none"
          >
            {PROTOCOL_FILTERS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        {protocol !== 'All' && (
          <p data-testid="filter-summary" className="text-sm text-slate-500">
            Showing {shownCount.toLocaleString()} of {reportable.length.toLocaleString()} issues involving {protocol}
          </p>
        )}
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold text-slate-900">Top issues</h3>
        <IssueList key={protocol} issues={issues} filter={protocol} />
      </div>

      <FlowTable
        testId="busiest-flows"
        title={protocol === 'All' ? 'Busiest flows' : `Busiest ${protocol} flows`}
        flows={busiest}
        emptyMessage={`No ${protocol} flows were found in this capture.`}
      />
      <FlowTable
        testId="slowest-flows"
        title={protocol === 'All' ? 'Slowest flows' : `Slowest ${protocol} flows`}
        flows={slowest}
        emptyMessage={
          protocol === 'All'
            ? 'No flows with measurable timing metrics.'
            : `None of the slowest flows in this capture are ${protocol}.`
        }
      />

      {d.recommendations.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-900">Recommendations</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-slate-600">
            {d.recommendations.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

/** The answer for a capture with nothing to analyze: no score, just why. */
function NothingToAnalyze({ result }: { result: EmptyResult }) {
  return (
    <div className="space-y-4 text-center" data-testid="nothing-to-analyze">
      <CaptureNotes issues={result.issues} />
      <p className="text-base font-medium text-slate-700">{result.message}</p>
      <p className="text-sm text-slate-500">There is nothing to score, so no health score is shown.</p>
    </div>
  )
}

interface ResultsCardProps {
  loading: boolean
  result: ApiResult | null
}

function ResultsCard({ loading, result }: ResultsCardProps) {
  return (
    <section aria-live="polite" className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      {loading ? (
        <p className="py-6 text-center text-sm text-slate-600">Analyzing capture…</p>
      ) : result ? (
        <>
          <h2 className="mb-4 truncate text-base font-semibold text-slate-900" title={result.file_name}>
            {result.file_name}
          </h2>
          {isEmptyResult(result) ? <NothingToAnalyze result={result} /> : <Report key={result.analysis_time} result={result} />}
        </>
      ) : (
        <div className="py-6 text-center">
          <p className="text-base font-medium text-slate-700">Upload a capture to begin analysis</p>
          <p className="mt-1 text-sm text-slate-500">
            The health score, root cause and issues will appear here.
          </p>
        </div>
      )}
    </section>
  )
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ApiResult | null>(null)
  const inFlight = useRef<AbortController | null>(null)

  // Abandon a running upload if the page goes away.
  useEffect(() => () => inFlight.current?.abort(), [])

  const handleSelect = (selected: File | null) => {
    setResult(null)
    if (selected && !isCaptureFile(selected)) {
      setFile(null)
      setError(`"${selected.name}" is not a capture file. Choose a .pcap or .pcapng file.`)
      return
    }
    setError(null)
    setFile(selected)
  }

  const handleAnalyze = async () => {
    if (!file || isLoading) return
    const controller = new AbortController()
    inFlight.current = controller
    setIsLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await analyzeCapture(file, controller.signal))
    } catch (err) {
      if (controller.signal.aborted) return
      setError(err instanceof ApiError ? err.message : 'Something went wrong while analyzing the capture.')
    } finally {
      if (inFlight.current === controller) {
        inFlight.current = null
        setIsLoading(false)
      }
    }
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <Header />
      <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">
        <UploadCard
          file={file}
          loading={isLoading}
          error={error}
          onSelect={handleSelect}
          onAnalyze={handleAnalyze}
        />
        <ResultsCard loading={isLoading} result={result} />
      </main>
    </div>
  )
}
