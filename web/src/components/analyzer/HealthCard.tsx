import { healthTone } from '../../format'
import { useCountUp } from '../../hooks/useCountUp'
import type { Diagnosis } from '../../types'
import MonoText from '../ui/MonoText'

/**
 * The health score as a prominent stat card, colored green, yellow or red,
 * with the primary cause and its confidence beside it.
 */
export default function HealthCard({ diagnosis }: { diagnosis: Diagnosis }) {
  const tone = healthTone(diagnosis.health_score)
  const shown = useCountUp(diagnosis.health_score, 1000)
  return (
    <div className={`relative overflow-hidden rounded-2xl border ${tone.ring} ${tone.bg} p-4 shadow-theme-xs md:px-6 md:py-4`}>
      <div className={`absolute inset-y-0 left-0 w-1.5 ${tone.bar}`} aria-hidden="true" />
      <div className="flex flex-wrap items-center gap-6 pl-2">
        <div
          className="flex-none text-center"
          role="img"
          aria-label={`Health score ${diagnosis.health_score} out of 100, ${tone.label}`}
        >
          <span className="text-sm text-gray-500 dark:text-gray-400">Health score</span>
          <div className="mt-1 flex items-baseline justify-center gap-1">
            <span data-testid="health-score" data-value={diagnosis.health_score} className={`text-title-md font-bold tabular-nums ${tone.text}`}>
              {shown}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">/100</span>
          </div>
          <span className={`mt-1 inline-block rounded-full bg-white dark:bg-gray-900 px-3 py-1 text-theme-xs font-semibold uppercase tracking-wide ${tone.text}`}>
            {tone.label}
          </span>
        </div>

        <div className="min-w-0 flex-1 basis-60">
          <p className="text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Primary cause</p>
          <p data-testid="primary-cause" className="mt-1 line-clamp-1 text-lg font-semibold text-gray-800 dark:text-white/90" title={diagnosis.primary_cause}>
            {diagnosis.primary_cause}
          </p>
          <p className="text-theme-sm text-gray-600 dark:text-gray-400">
            Confidence: <span className="font-medium">{diagnosis.confidence}</span>
          </p>
          <p className="mt-1 line-clamp-1 text-theme-sm text-gray-500 dark:text-gray-400" title={diagnosis.summary}>
            <MonoText>{diagnosis.summary}</MonoText>
          </p>
        </div>
      </div>
    </div>
  )
}
