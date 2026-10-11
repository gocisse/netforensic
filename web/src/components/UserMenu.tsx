import { useEffect, useRef, useState } from 'react'

interface Props {
  username: string
  onChangePassword: () => void
  onLogout: () => void
}

/** The user's dropdown in the navigation bar: change password and sign out. */
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

  const item = 'block w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-50'
  return (
    <div ref={root} className="relative" data-testid="user-menu">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        data-testid="user-menu-button"
        className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-slate-100"
      >
        <span aria-hidden="true" className="flex h-8 w-8 items-center justify-center rounded-full bg-indigo-100 text-sm font-semibold uppercase text-indigo-700">
          {username.charAt(0) || '?'}
        </span>
        <span className="text-sm font-medium text-slate-700">{username}</span>
        <span aria-hidden="true" className="text-xs text-slate-400">
          ▾
        </span>
      </button>
      {open && (
        <div role="menu" className="absolute right-0 z-40 mt-2 w-48 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-lg">
          <button
            type="button"
            role="menuitem"
            className={item}
            onClick={() => {
              setOpen(false)
              onChangePassword()
            }}
          >
            Change Password
          </button>
          <button
            type="button"
            role="menuitem"
            className={`${item} border-t border-slate-100`}
            onClick={() => {
              setOpen(false)
              onLogout()
            }}
          >
            Logout
          </button>
        </div>
      )}
    </div>
  )
}
