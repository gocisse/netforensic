import { AlertIcon, ErrorIcon, InfoIcon } from '../../icons'
import { plainIssue, plainSeverity } from '../../plainLanguage'
import type { Issue } from '../../types'
import { Card } from '../ui/Card'

const STYLE = {
  error: { icon: ErrorIcon, tint: 'bg-error-50 dark:bg-error-500/15 text-error-600 dark:text-error-400', chip: 'bg-error-50 dark:bg-error-500/15 text-error-700 dark:text-error-400' },
  warning: { icon: AlertIcon, tint: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400', chip: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400' },
  info: { icon: InfoIcon, tint: 'bg-blue-light-50 dark:bg-blue-light-500/15 text-blue-light-700 dark:text-blue-light-400', chip: 'bg-blue-light-50 dark:bg-blue-light-500/15 text-blue-light-700 dark:text-blue-light-400' },
}

/**
 * An issue in plain words: an icon, a title without jargon, what it means and
 * what to do, in numbered steps. The Wireshark filter, the protocol names and
 * the raw numbers are left out (they are in Senior mode).
 */
export default function JuniorIssueCard({ issue }: { issue: Issue }) {
  const plain = plainIssue(issue)
  const sev = plainSeverity(issue.severity)
  const style = STYLE[sev.kind]
  const Icon = style.icon
  const times = issue.count ?? 1
  return (
    <Card data-testid="junior-issue-card" className="p-6 transition-shadow hover:shadow-theme-md sm:p-6">
      <div className="flex items-start gap-4">
        <span className={`flex h-12 w-12 flex-none items-center justify-center rounded-xl ${style.tint}`} data-testid="junior-icon" data-kind={sev.kind}>
          <Icon className="h-6 w-6" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-3">
            <h3 className="text-base font-semibold text-gray-800 dark:text-white/90" data-testid="junior-issue-title">
              {plain.title}
            </h3>
            <span className={`rounded-full px-3 py-1 text-theme-xs font-semibold ${style.chip}`}>{sev.label}</span>
            {times > 1 && <span className="text-theme-xs text-gray-600 dark:text-gray-400">Happened {times.toLocaleString()} times</span>}
          </div>

          <div className="mt-4">
            <h4 className="text-theme-xs font-semibold uppercase tracking-wide text-gray-600 dark:text-gray-400">What this means</h4>
            <p className="mt-1 text-theme-sm text-gray-700 dark:text-gray-300" data-testid="junior-meaning">
              {plain.meaning}
            </p>
          </div>
          <div className="mt-4">
            <h4 className="text-theme-xs font-semibold uppercase tracking-wide text-gray-600 dark:text-gray-400">What to do</h4>
            <ol className="mt-1 list-decimal space-y-1 pl-6 text-theme-sm text-gray-700 dark:text-gray-300" data-testid="junior-steps">
              {plain.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </div>
        </div>
      </div>
    </Card>
  )
}
