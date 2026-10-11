import { pageInfo } from '../../protocols'
import ProtocolPage from './ProtocolPage'

const info = pageInfo('http')

/** HTTP issues: see ProtocolPage. */
export default function HTTPPage() {
  return <ProtocolPage info={info} />
}
