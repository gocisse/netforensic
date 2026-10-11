import { CloseIcon, MenuIcon } from '../icons'
import Logo from '../components/Logo'
import UserMenu from '../components/UserMenu'

interface Props {
  username: string
  mobileOpen: boolean
  onToggleSidebar: () => void
  onChangePassword: () => void
  onLogout: () => void
}

/** The top bar: the sidebar toggle on the left and the user menu on the right. */
export default function Topbar({ username, mobileOpen, onToggleSidebar, onChangePassword, onLogout }: Props) {
  return (
    <header className="sticky top-0 z-40 flex w-full border-b border-gray-200 bg-white">
      <div className="flex w-full items-center justify-between gap-3 px-4 py-3 md:px-6">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onToggleSidebar}
            aria-label={mobileOpen ? 'Close the sidebar' : 'Open the sidebar'}
            aria-expanded={mobileOpen}
            data-testid="sidebar-toggle"
            className="flex h-10 w-10 items-center justify-center rounded-lg border border-gray-200 text-gray-500 hover:bg-gray-100"
          >
            {mobileOpen && <CloseIcon className="h-5 w-5 xl:hidden" />}
            <MenuIcon className={mobileOpen ? 'hidden h-5 w-5 xl:block' : 'h-5 w-5'} />
          </button>
          <div className="xl:hidden">
            <Logo />
          </div>
        </div>
        <UserMenu username={username} onChangePassword={onChangePassword} onLogout={onLogout} />
      </div>
    </header>
  )
}
