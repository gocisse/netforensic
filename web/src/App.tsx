import { Navigate, Route, Routes } from 'react-router-dom'
import { AnalysisProvider } from './analysis/AnalysisProvider'
import { AuthProvider } from './auth/AuthProvider'
import { ToastProvider } from './toast/ToastProvider'
import { useAuth } from './auth/useAuth'
import ForcedPasswordChange from './components/ForcedPasswordChange'
import LoginPage from './components/LoginPage'
import Shortcuts from './shortcuts/Shortcuts'
import DashboardLayout from './layout/DashboardLayout'
import AnalysisLayout from './pages/AnalysisLayout'
import Analyzer from './pages/Analyzer'
import Overview from './pages/Overview'
import DHCPv6Page from './pages/protocol/DHCPv6Page'
import DNSPage from './pages/protocol/DNSPage'
import HTTPPage from './pages/protocol/HTTPPage'
import QUICPage from './pages/protocol/QUICPage'
import SIPPage from './pages/protocol/SIPPage'
import TCPPage from './pages/protocol/TCPPage'
import TLSPage from './pages/protocol/TLSPage'
import UDPPage from './pages/protocol/UDPPage'

/**
 * Decides what the user sees: the sign-in page without a session, the forced
 * password change while the default password is in use, else the dashboard
 * with its pages:
 *
 *	/                       upload a capture
 *	/analysis/:id           the overview of an analysis
 *	/analysis/:id/<proto>   the issues of one protocol (tcp, udp, dns, http, tls, sip, dhcpv6, quic)
 */
function Gate() {
  const { session } = useAuth()
  if (!session) return <LoginPage />
  if (session.mustChangePassword) return <ForcedPasswordChange />
  return (
    <>
      <Shortcuts />
      <DashboardLayout>
        <Routes>
          <Route path="/" element={<Analyzer />} />
          <Route path="/analysis/:id" element={<AnalysisLayout />}>
            <Route index element={<Overview />} />
            <Route path="tcp" element={<TCPPage />} />
            <Route path="udp" element={<UDPPage />} />
            <Route path="dns" element={<DNSPage />} />
            <Route path="http" element={<HTTPPage />} />
            <Route path="tls" element={<TLSPage />} />
            <Route path="sip" element={<SIPPage />} />
            <Route path="dhcpv6" element={<DHCPv6Page />} />
            <Route path="quic" element={<QUICPage />} />
            <Route path="*" element={<Navigate to=".." replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </DashboardLayout>
    </>
  )
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <AnalysisProvider>
            <Gate />
        </AnalysisProvider>
      </AuthProvider>
    </ToastProvider>
  )
}
