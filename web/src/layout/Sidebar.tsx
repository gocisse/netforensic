import type { ComponentType, SVGProps } from 'react'
import { GridIcon, LockIcon, LogoutIcon } from '../icons'
import Logo from '../components/Logo'

interface Props {
  /** The desktop sidebar shows icons only. */
  collapsed: boolean
  /** The small-screen drawer is open. */
  mobileOpen: boolean
  onChangePassword: () => void
  onLogout: () => void
  onNavigate: () => void
}

interface ItemProps {
  icon: ComponentType<SVGProps<SVGSVGElement>>
  label: string
  collapsed: boolean
  active?: boolean
  onClick?: () => void
}

function Item({ icon: Icon, label, collapsed, active = false, onClick }: ItemProps) {
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        aria-current={active ? 'page' : undefined}
        title={collapsed ? label : undefined}
        className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-theme-sm font-medium transition ${
          active ? 'bg-brand-50 text-brand-500' : 'text-gray-700 hover:bg-gray-100 hover:text-gray-700'
        } ${collapsed ? 'xl:justify-center xl:px-0' : ''}`}
      >
        <Icon className={`h-6 w-6 flex-none ${active ? 'text-brand-500' : 'text-gray-500 group-hover:text-gray-700'}`} />
        <span className={collapsed ? 'xl:hidden' : ''}>{label}</span>
      </button>
    </li>
  )
}

function Group({ title, collapsed, children }: { title: string; collapsed: boolean; children: React.ReactNode }) {
  return (
    <div>
      <h2 className={`mb-3 px-3 text-xs uppercase leading-5 text-gray-400 ${collapsed ? 'xl:text-center xl:px-0' : ''}`}>
        <span className={collapsed ? 'xl:hidden' : ''}>{title}</span>
        {collapsed && <span className="hidden xl:inline">···</span>}
      </h2>
      <ul className="flex flex-col gap-1">{children}</ul>
    </div>
  )
}

/**
 * The navigation sidebar. From the xl breakpoint it is fixed to the left, wide
 * or collapsed to icons; below that it is a drawer that slides in over the page.
 */
export default function Sidebar({ collapsed, mobileOpen, onChangePassword, onLogout, onNavigate }: Props) {
  return (
    <aside
      data-testid="sidebar"
      aria-label="Sidebar"
      className={`fixed left-0 top-0 z-50 flex h-screen w-72.5 flex-col border-r border-gray-200 bg-white px-5 transition-all duration-300 ease-in-out xl:translate-x-0 ${
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      } ${collapsed ? 'xl:w-22.5' : 'xl:w-72.5'}`}
    >
      <div className={`flex py-8 ${collapsed ? 'xl:justify-center' : ''}`}>
        <Logo showName={!collapsed} />
      </div>

      <nav className="flex flex-1 flex-col gap-6 overflow-y-auto" aria-label="Main">
        <Group title="Menu" collapsed={collapsed}>
          <Item icon={GridIcon} label="Analyzer" collapsed={collapsed} active onClick={onNavigate} />
        </Group>
        <Group title="Account" collapsed={collapsed}>
          <Item
            icon={LockIcon}
            label="Change password"
            collapsed={collapsed}
            onClick={() => {
              onNavigate()
              onChangePassword()
            }}
          />
          <Item icon={LogoutIcon} label="Sign out" collapsed={collapsed} onClick={onLogout} />
        </Group>
      </nav>

      <p className={`pb-5 text-theme-xs text-gray-400 ${collapsed ? 'xl:hidden' : ''}`}>Packet capture forensics</p>
    </aside>
  )
}
