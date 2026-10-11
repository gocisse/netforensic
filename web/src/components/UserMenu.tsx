import { useEffect, useRef, useState } from 'react'
import { ChevronDownIcon, LockIcon, LogoutIcon } from '../icons'

interface Props {
  username: string
  onChangePassword: () => void
  onLogout: () => void
}

/** The user's dropdown in the top bar: change password and sign out. */
export default function UserMenu({ username, onChangePassword, onLogout }: Props) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const item = 'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-theme-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white'
  return (
    <div ref={root} className="relative" data-testid="user-menu">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        data-testid="user-menu-button"
        className="flex items-center gap-3 rounded-lg px-1 py-1 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
      >
        <span aria-hidden="true" className="flex h-11 w-11 items-center justify-center rounded-full bg-brand-50 dark:bg-brand-500/15 text-base font-semibold uppercase text-brand-600 dark:text-brand-400">
          {username.charAt(0) || '?'}
        </span>
        <span className="hidden text-theme-sm font-medium sm:block">{username}</span>
        <ChevronDownIcon className={`hidden h-5 w-5 text-gray-500 dark:text-gray-400 transition-transform sm:block ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 z-99999 mt-2 w-64 rounded-2xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-3 shadow-theme-lg">
          <div className="px-3 pb-3">
            <span className="block text-theme-sm font-medium text-gray-700 dark:text-gray-300">{username}</span>
            <span className="mt-1 block text-theme-xs text-gray-500 dark:text-gray-400">Signed in</span>
          </div>
          <div className="border-t border-gray-200 dark:border-gray-800 pt-2">
            <button
              type="button"
              role="menuitem"
              className={item}
              onClick={() => {
                setOpen(false)
                onChangePassword()
              }}
            >
              <LockIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
              Change Password
            </button>
            <button
              type="button"
              role="menuitem"
              className={item}
              onClick={() => {
                setOpen(false)
                onLogout()
              }}
            >
              <LogoutIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
              Logout
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
