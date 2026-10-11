import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('tls')

/** TLS issues: see ProtocolPage. */
export default function TLSPage() {
  return <ProtocolPage info={info} />
}
