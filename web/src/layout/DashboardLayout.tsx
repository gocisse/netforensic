import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useAuth } from '../auth/useAuth'
import Alert from '../components/ui/Alert'
import ChangePasswordForm from '../components/ChangePasswordForm'
import Modal from '../components/Modal'
import Sidebar from './Sidebar'
import Topbar from './Topbar'

const XL = '(min-width: 1280px)'

/**
 * The signed-in frame: a sidebar (a drawer on small screens), a top bar with
 * the user menu, and the page content.
 */
export default function DashboardLayout({ children }: { children: ReactNode }) {
  const { session, logout } = useAuth()
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [changing, setChanging] = useState(false)
  const [changed, setChanged] = useState(false)

  // The drawer belongs to small screens: leave it closed when the window grows.
  useEffect(() => {
    const query = window.matchMedia(XL)
    const onChange = () => {
      if (query.matches) setMobileOpen(false)
    }
    query.addEventListener('change', onChange)
    return () => query.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    if (!mobileOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileOpen(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [mobileOpen])

  // One button, two jobs: the drawer below xl, the icon-only mode from xl.
  const toggleSidebar = () => {
    if (window.matchMedia(XL).matches) setCollapsed((v) => !v)
    else setMobileOpen((v) => !v)
  }

  const openChangePassword = () => {
    setChanged(false)
    setChanging(true)
  }

  return (
    <div className="min-h-screen xl:flex">
      <Sidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onChangePassword={openChangePassword}
        onLogout={logout}
        onNavigate={() => setMobileOpen(false)}
      />
      {mobileOpen && (
        <div
          data-testid="sidebar-backdrop"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-gray-900/50 xl:hidden"
          aria-hidden="true"
        />
      )}

      <div className={`min-w-0 flex-1 transition-all duration-300 ease-in-out ${collapsed ? 'xl:ml-22.5' : 'xl:ml-72.5'}`}>
        <Topbar
          username={session?.username ?? ''}
          mobileOpen={mobileOpen}
          onToggleSidebar={toggleSidebar}
          onChangePassword={openChangePassword}
          onLogout={logout}
        />
        <div className="mx-auto max-w-screen-2xl p-4 md:p-6">
          {changed && (
            <div className="mb-4" data-testid="password-changed">
              <Alert variant="success">Your password was changed.</Alert>
            </div>
          )}
          <main className="space-y-6">{children}</main>
        </div>
      </div>

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
