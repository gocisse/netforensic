import { useDashboardMode } from '../mode/useDashboardMode'
import JuniorFlowTable from './junior/JuniorFlowTable'
import SeniorFlowTable from './SeniorFlowTable'
import type { Props } from './SeniorFlowTable'

/** A table of flows: From, To, What and Status in Junior mode, the full columns in Senior mode. */
export default function FlowTable(props: Props) {
  const { mode } = useDashboardMode()
  return mode === 'junior' ? <JuniorFlowTable title={props.title} flows={props.flows} emptyMessage={props.emptyMessage} /> : <SeniorFlowTable {...props} />
}
