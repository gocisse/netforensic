import { useDashboardMode } from '../mode/useDashboardMode'
import JuniorProtocolDistribution from './junior/JuniorProtocolDistribution'
import SeniorProtocolDistribution from './SeniorProtocolDistribution'
import type { Props } from './SeniorProtocolDistribution'

/** The traffic composition: grouped, labelled bars in Junior mode, raw protocol names in Senior mode. */
export default function ProtocolDistribution(props: Props) {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorProtocolDistribution stats={props.stats} /> : <SeniorProtocolDistribution {...props} />
}
