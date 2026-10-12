import { Navigate, useLocation } from 'react-router-dom'
import { useAnalysisView } from '../analysis/view'

/** What /analysis/:id opens: Bad Traffic if the capture has issues, else Good Traffic. */
export default function DefaultTab() {
  const { id, reportableTotal } = useAnalysisView()
  const { search } = useLocation()
  return <Navigate to={{ pathname: `/analysis/${id}/${reportableTotal > 0 ? 'bad' : 'good'}`, search }} replace />
}
