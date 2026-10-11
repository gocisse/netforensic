import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('tcp')

/** TCP issues: see ProtocolPage. */
export default function TCPPage() {
  return <ProtocolPage info={info} />
}
