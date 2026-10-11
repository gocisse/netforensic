import { AuthProvider } from './auth/AuthProvider'
import { useAuth } from './auth/useAuth'
import ForcedPasswordChange from './components/ForcedPasswordChange'
import LoginPage from './components/LoginPage'
import DashboardLayout from './layout/DashboardLayout'
import Analyzer from './pages/Analyzer'

/**
 * Decides what the user sees: the sign-in page without a session, the forced
 * password change while the default password is in use, else the dashboard.
 */
function Gate() {
  const { session } = useAuth()
  if (!session) return <LoginPage />
  if (session.mustChangePassword) return <ForcedPasswordChange />
  return (
    <DashboardLayout>
      <Analyzer />
    </DashboardLayout>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  )
}
