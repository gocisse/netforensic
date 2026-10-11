import { healthLight, plainRootCause } from '../../plainLanguage'
import type { Light } from '../../plainLanguage'
import type { Diagnosis } from '../../types'

const LIGHTS: { light: Light; on: string; off: string }[] = [
  { light: 'red', on: 'bg-error-500 shadow-[0_0_14px_rgba(240,68,56,0.7)]', off: 'bg-error-500/20' },
  { light: 'yellow', on: 'bg-warning-400 shadow-[0_0_14px_rgba(253,176,34,0.7)]', off: 'bg-warning-400/20' },
  { light: 'green', on: 'bg-success-500 shadow-[0_0_14px_rgba(18,183,106,0.7)]', off: 'bg-success-500/20' },
]

const TONE: Record<Light, { ring: string; bg: string; text: string }> = {
  green: { ring: 'border-success-200 dark:border-success-500/40', bg: 'bg-success-25 dark:bg-success-500/10', text: 'text-success-700 dark:text-success-400' },
  yellow: { ring: 'border-warning-200 dark:border-warning-500/40', bg: 'bg-warning-25 dark:bg-warning-500/10', text: 'text-warning-700 dark:text-warning-400' },
  red: { ring: 'border-error-200 dark:border-error-500/40', bg: 'bg-error-25 dark:bg-error-500/10', text: 'text-error-700 dark:text-error-400' },
}

/**
 * The health score as a traffic light with a sentence, and the main cause in
 * plain words. No score, no technical terms.
 */
export default function JuniorHealthCard({ diagnosis }: { diagnosis: Diagnosis }) {
  const h = healthLight(diagnosis.health_score)
  const cause = plainRootCause(diagnosis.primary_cause)
  const tone = TONE[h.light]
  return (
    <div className={`rounded-2xl border ${tone.ring} ${tone.bg} p-6 shadow-theme-xs`} data-testid="junior-health" data-light={h.light}>
      <div className="flex flex-wrap items-center gap-6">
        <div role="img" aria-label={`Traffic light: ${h.light}`} className="flex flex-none flex-col gap-2 rounded-full bg-gray-800 dark:bg-gray-950 p-3" data-testid="traffic-light">
          {LIGHTS.map((l) => (
            <span key={l.light} data-light={l.light} data-on={l.light === h.light} className={`block h-8 w-8 rounded-full transition-colors ${l.light === h.light ? l.on : l.off}`} />
          ))}
        </div>
        <div className="min-w-0 flex-1 basis-60">
          <h2 className={`text-title-sm font-bold ${tone.text}`} data-testid="junior-headline">
            {h.headline}
          </h2>
          <p className="mt-1 text-theme-sm text-gray-700 dark:text-gray-300">{h.detail}</p>
          {h.light !== 'green' || diagnosis.primary_cause !== 'No significant issues detected' ? (
            <div className="mt-4 rounded-xl bg-white/70 dark:bg-gray-900/60 p-4" data-testid="junior-cause">
              <p className="text-theme-xs font-semibold uppercase tracking-wide text-gray-600 dark:text-gray-400">The main problem</p>
              <p className="mt-1 text-base font-semibold text-gray-800 dark:text-white/90">{cause.title}</p>
              <p className="mt-1 text-theme-sm text-gray-700 dark:text-gray-300">{cause.text}</p>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
