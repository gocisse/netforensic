import { useDashboardMode } from '../mode/useDashboardMode'
import JuniorOverview from './JuniorOverview'
import SeniorOverview from './SeniorOverview'

/** The overview of an analysis, in plain language (Junior) or with the full technical detail (Senior). */
export default function Overview() {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorOverview /> : <SeniorOverview />
}
