import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('dns')

/** DNS issues: see ProtocolPage. */
export default function DNSPage() {
  return <ProtocolPage info={info} />
}
