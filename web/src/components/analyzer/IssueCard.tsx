import { useDashboardMode } from '../../mode/useDashboardMode'
import JuniorIssueCard from '../junior/JuniorIssueCard'
import SeniorIssueCard from './SeniorIssueCard'
import type { Props } from './SeniorIssueCard'

/** One issue: a simplified card in Junior mode, the full card with the Wireshark filter in Senior mode. */
export default function IssueCard(props: Props) {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorIssueCard issue={props.issue} /> : <SeniorIssueCard {...props} />
}
