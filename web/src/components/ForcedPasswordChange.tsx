import { useAuth } from '../auth/useAuth'
import AuthLayout from '../layout/AuthLayout'
import ChangePasswordForm from './ChangePasswordForm'

/**
 * Shown instead of the app while the default password is still in use. There
 * is no way past it except changing the password (or signing out).
 */
export default function ForcedPasswordChange() {
  const { session, logout } = useAuth()
  return (
    <AuthLayout
      data-testid="forced-password-change"
      title="Choose a new password"
      subtitle={
        <>
          {session?.username ? `${session.username}, you` : 'You'} signed in with the default password. Set a new one
          before using the analyzer; enter the default password as the current password.
        </>
      }
      footer={
        <button type="button" onClick={logout} className="font-medium text-gray-500 hover:text-gray-800">
          Sign out
        </button>
      }
    >
      <ChangePasswordForm onDone={() => undefined} />
    </AuthLayout>
  )
}
