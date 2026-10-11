import { useAuth } from '../auth/useAuth'
import ChangePasswordForm from './ChangePasswordForm'
import Logo from './Logo'

/**
 * Shown instead of the app while the default password is still in use. There
 * is no way past it except changing the password (or signing out).
 */
export default function ForcedPasswordChange() {
  const { session, logout } = useAuth()
  return (
    <div data-testid="forced-password-change" className="flex min-h-screen flex-col items-center justify-center bg-slate-100 px-4">
      <Logo size="lg" />
      <div className="mt-8 w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h1 className="text-lg font-semibold text-slate-900">Choose a new password</h1>
        <p className="mt-2 text-sm text-slate-600">
          {session?.username ? `${session.username}, you` : 'You'} signed in with the default password. Set a new one
          before using the analyzer; enter the default password as the current password.
        </p>
        <ChangePasswordForm onDone={() => undefined} />
        <div className="mt-4 border-t border-slate-100 pt-3 text-center">
          <button type="button" onClick={logout} className="text-sm text-slate-500 hover:text-slate-800">
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}
