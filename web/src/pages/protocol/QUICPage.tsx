import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('quic')

/** QUIC issues: see ProtocolPage. */
export default function QUICPage() {
  return <ProtocolPage info={info} />
}
