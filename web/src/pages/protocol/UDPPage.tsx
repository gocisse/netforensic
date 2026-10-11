import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('udp')

/** UDP issues: see ProtocolPage. */
export default function UDPPage() {
  return <ProtocolPage info={info} />
}
