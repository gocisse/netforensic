import { useDashboardMode } from '../../mode/useDashboardMode'
import type { Diagnosis } from '../../types'
import JuniorHealthCard from '../junior/JuniorHealthCard'
import SeniorHealthCard from './SeniorHealthCard'

/** The health score: a traffic light in Junior mode, the score and technical cause in Senior mode. */
export default function HealthCard({ diagnosis }: { diagnosis: Diagnosis }) {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorHealthCard diagnosis={diagnosis} /> : <SeniorHealthCard diagnosis={diagnosis} />
}
