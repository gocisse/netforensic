import { useState } from 'react'
import type { ReactNode } from 'react'
import { useAuth } from '../auth/useAuth'
import ChangePasswordForm from './ChangePasswordForm'
import Logo from './Logo'
import Modal from './Modal'
import UserMenu from './UserMenu'

/** The signed-in frame: a navigation bar with the user menu above the page content. */
export default function DashboardLayout({ children }: { children: ReactNode }) {
  const { session, logout } = useAuth()
  const [changing, setChanging] = useState(false)
  const [changed, setChanged] = useState(false)

  return (
    <div className="min-h-screen bg-slate-100 text-slate-900">
      <nav className="border-b border-slate-200 bg-white" aria-label="Main">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
          <Logo />
          <UserMenu
            username={session?.username ?? ''}
            onChangePassword={() => {
              setChanged(false)
              setChanging(true)
            }}
            onLogout={logout}
          />
        </div>
      </nav>

      {changed && (
        <div role="status" data-testid="password-changed" className="mx-auto mt-4 max-w-5xl px-6">
          <p className="rounded-md bg-green-50 px-4 py-2 text-sm text-green-800">Your password was changed.</p>
        </div>
      )}

      <main className="mx-auto max-w-5xl space-y-6 px-6 py-8">{children}</main>

      {changing && (
        <Modal title="Change password" onClose={() => setChanging(false)}>
          <ChangePasswordForm
            onDone={() => {
              setChanging(false)
              setChanged(true)
            }}
            onCancel={() => setChanging(false)}
          />
        </Modal>
      )}
    </div>
  )
}
