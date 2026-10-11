import { healthTone } from '../../format'
import type { Diagnosis } from '../../types'

/**
 * The health score as a prominent stat card, colored green, yellow or red,
 * with the primary cause and its confidence beside it.
 */
export default function HealthCard({ diagnosis }: { diagnosis: Diagnosis }) {
  const tone = healthTone(diagnosis.health_score)
  return (
    <div className={`relative overflow-hidden rounded-2xl border ${tone.ring} ${tone.bg} p-5 shadow-theme-xs md:p-6 sm:col-span-2`}>
      <div className={`absolute inset-y-0 left-0 w-1.5 ${tone.bar}`} aria-hidden="true" />
      <div className="flex flex-wrap items-center gap-6 pl-2">
        <div
          className="flex-none text-center"
          role="img"
          aria-label={`Health score ${diagnosis.health_score} out of 100, ${tone.label}`}
        >
          <span className="text-sm text-gray-500">Health score</span>
          <div className="mt-1 flex items-baseline justify-center gap-1">
            <span data-testid="health-score" className={`text-title-md font-bold ${tone.text}`}>
              {diagnosis.health_score}
            </span>
            <span className="text-sm text-gray-400">/100</span>
          </div>
          <span className={`mt-1 inline-block rounded-full bg-white px-2.5 py-0.5 text-theme-xs font-semibold uppercase tracking-wide ${tone.text}`}>
            {tone.label}
          </span>
        </div>

        <div className="min-w-0 flex-1 basis-60">
          <p className="text-theme-xs font-semibold uppercase tracking-wide text-gray-500">Primary cause</p>
          <p data-testid="primary-cause" className="mt-1 text-lg font-semibold text-gray-800">
            {diagnosis.primary_cause}
          </p>
          <p className="mt-1 text-theme-sm text-gray-600">
            Confidence: <span className="font-medium">{diagnosis.confidence}</span>
          </p>
          <p className="mt-2 text-theme-sm text-gray-500">{diagnosis.summary}</p>
        </div>
      </div>
    </div>
  )
}
