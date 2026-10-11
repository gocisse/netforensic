import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('sip')

/** SIP issues: see ProtocolPage. */
export default function SIPPage() {
  return <ProtocolPage info={info} />
}
