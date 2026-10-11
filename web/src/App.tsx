import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'

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

interface ResultsCardProps {
  loading: boolean
  analyzedName: string | null
}

function ResultsCard({ loading, analyzedName }: ResultsCardProps) {
  return (
    <section
      aria-live="polite"
      className="rounded-xl border border-slate-200 bg-white p-10 text-center shadow-sm"
    >
      {loading ? (
        <p className="text-sm text-slate-600">Analyzing capture…</p>
      ) : analyzedName ? (
        <>
          <p className="text-sm font-medium text-slate-900">{analyzedName}</p>
          <p className="mt-1 text-sm text-slate-500">
            Analysis is not connected to a server yet. Results will appear here.
          </p>
        </>
      ) : (
        <>
          <p className="text-base font-medium text-slate-700">Upload a capture to begin analysis</p>
          <p className="mt-1 text-sm text-slate-500">
            The health score, root cause, timeline and issues will appear here.
          </p>
        </>
      )}
    </section>
  )
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [analyzedName, setAnalyzedName] = useState<string | null>(null)

  const handleSelect = (selected: File | null) => {
    setAnalyzedName(null)
    if (selected && !isCaptureFile(selected)) {
      setFile(null)
      setError(`"${selected.name}" is not a capture file. Choose a .pcap or .pcapng file.`)
      return
    }
    setError(null)
    setFile(selected)
  }

  // Placeholder: the upload endpoint arrives with the Go server.
  const handleAnalyze = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    await new Promise((resolve) => setTimeout(resolve, 800))
    setAnalyzedName(file.name)
    setLoading(false)
  }

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <Header />
      <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">
        <UploadCard
          file={file}
          loading={loading}
          error={error}
          onSelect={handleSelect}
          onAnalyze={handleAnalyze}
        />
        <ResultsCard loading={loading} analyzedName={analyzedName} />
      </main>
    </div>
  )
}
