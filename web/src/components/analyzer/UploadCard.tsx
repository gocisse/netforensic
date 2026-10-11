import { useRef, useState } from 'react'
import type { ChangeEvent, DragEvent } from 'react'
import { ACCEPTED_EXTENSIONS } from '../../format'
import { FileIcon, UploadIcon } from '../../icons'
import Alert from '../ui/Alert'
import Button from '../ui/Button'
import { Card, CardBody, CardHeader } from '../ui/Card'

/** Formats a byte count for display, for example "4.9 MB". */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

interface Props {
  file: File | null
  loading: boolean
  error: string | null
  onSelect: (file: File | null) => void
  onAnalyze: () => void
}

/** The capture dropzone and the Analyze button. */
export default function UploadCard({ file, loading, error, onSelect, onAnalyze }: Props) {
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
    <Card data-testid="upload-card">
      <CardHeader
        title="Capture file"
        description={
          <>
            Choose a <code className="rounded bg-gray-100 px-1 text-theme-xs">.pcap</code> or{' '}
            <code className="rounded bg-gray-100 px-1 text-theme-xs">.pcapng</code> file to analyze.
          </>
        }
      />
      <CardBody>
        <label
          htmlFor="capture-file"
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-10 text-center transition-colors ${
            dragging ? 'border-brand-500 bg-gray-100' : 'border-gray-300 bg-gray-50 hover:border-brand-500'
          } ${loading ? 'pointer-events-none opacity-60' : ''}`}
        >
          {file ? (
            <>
              <span className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-brand-50 text-brand-500">
                <FileIcon className="h-7 w-7" />
              </span>
              <span className="text-theme-sm font-semibold text-gray-800">{file.name}</span>
              <span className="mt-1 text-theme-xs text-gray-500">{formatSize(file.size)}</span>
              <span className="mt-3 text-theme-xs font-medium text-brand-500">Click or drop to choose a different file</span>
            </>
          ) : (
            <>
              <span className="mb-3 flex h-14 w-14 items-center justify-center rounded-full bg-gray-200 text-gray-600">
                <UploadIcon className="h-7 w-7" />
              </span>
              <span className="text-theme-sm font-semibold text-gray-800">Click to choose a file, or drag one here</span>
              <span className="mt-1 text-theme-xs text-gray-500">Accepted: .pcap, .pcapng</span>
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
          <div className="mt-4">
            <Alert variant="error" role="alert">
              {error}
            </Alert>
          </div>
        )}

        <div className="mt-5 flex items-center justify-end gap-3">
          {file && !loading && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                onSelect(null)
                if (inputRef.current) inputRef.current.value = ''
              }}
            >
              Clear
            </Button>
          )}
          <Button size="sm" onClick={onAnalyze} disabled={!file} loading={loading}>
            {loading ? 'Analyzing…' : 'Analyze'}
          </Button>
        </div>
      </CardBody>
    </Card>
  )
}
