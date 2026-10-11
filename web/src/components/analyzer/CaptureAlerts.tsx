import { isCaptureNote } from '../../format'
import type { Issue } from '../../types'
import Alert from '../ui/Alert'

/** Banners for problems with the capture file itself: truncation, skipped frames. */
export default function CaptureAlerts({ issues }: { issues: Issue[] }) {
  const notes = issues.filter(isCaptureNote)
  if (notes.length === 0) return null
  return (
    <div className="space-y-3" data-testid="capture-alerts">
      {notes.map((n) => (
        <Alert key={n.id} variant={n.title === 'Truncated Capture' ? 'warning' : 'info'} title={n.title}>
          {n.description}
        </Alert>
      ))}
    </div>
  )
}
