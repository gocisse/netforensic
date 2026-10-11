import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('dhcpv6')

/** DHCPv6 issues: see ProtocolPage. */
export default function DHCPv6Page() {
  return <ProtocolPage info={info} />
}
