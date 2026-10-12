import { useLoadProgress } from '../../analysis/useLoadProgress'
import { Card } from '../ui/Card'

function Row({ label, loaded, total, testId }: { label: string; loaded: number; total: number; testId: string }) {
  const percent = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : 100
  return (
    <div data-testid={testId} data-loaded={loaded} data-total={total}>
      <div className="flex items-center justify-between gap-4 text-theme-sm">
        <span className="font-medium text-gray-800 dark:text-white/90">
          {label}: {loaded.toLocaleString()} / {total.toLocaleString()}
        </span>
        <span className="tabular-nums text-gray-500 dark:text-gray-400">{percent}%</span>
      </div>
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={loaded}
        className="mt-2 h-2 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800"
      >
        <div className="h-full rounded-full bg-brand-500 transition-[width] duration-150" style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

/** While the lists of an analysis are still arriving: how far each has got. Nothing once they are all here. */
export default function LoadProgressBar() {
  const progress = useLoadProgress()
  if (!progress) return null
  const issues = progress.issues.loaded < progress.issues.total
  const flows = progress.flows.loaded < progress.flows.total
  if (!issues && !flows) return null
  return (
    <Card data-testid="load-progress">
      <div className="space-y-4 p-4 sm:p-6">
        {issues && <Row label="Loading issues" loaded={progress.issues.loaded} total={progress.issues.total} testId="load-progress-issues" />}
        {flows && <Row label="Loading flows" loaded={progress.flows.loaded} total={progress.flows.total} testId="load-progress-flows" />}
      </div>
    </Card>
  )
}
