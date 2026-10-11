import { useDashboardMode } from '../../mode/useDashboardMode'
import type { ProtocolPageInfo } from '../../protocols'
import JuniorProtocolPage from './JuniorProtocolPage'
import SeniorProtocolPage from './SeniorProtocolPage'

/** The page of one protocol: plain language in Junior mode, the full technical page in Senior mode. */
export default function ProtocolPage({ info }: { info: ProtocolPageInfo }) {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorProtocolPage info={info} /> : <SeniorProtocolPage info={info} />
}
