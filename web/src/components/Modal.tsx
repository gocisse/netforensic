import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import { CloseIcon } from '../icons'

interface Props {
  title: string
  onClose: () => void
  children: ReactNode
}

/** A centered dialog over a dimmed backdrop. Escape and a click outside close it. */
export default function Modal({ title, onClose, children }: Props) {
  const dialog = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    dialog.current?.querySelector<HTMLElement>('input, button')?.focus()
  }, [])

  return (
    <div
      className="fixed inset-0 z-99999 flex items-center justify-center bg-gray-900/50 px-4 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div ref={dialog} role="dialog" aria-modal="true" aria-label={title} className="relative w-full max-w-md rounded-2xl bg-white dark:bg-gray-900 p-6 shadow-theme-xl sm:p-8">
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="absolute right-4 top-4 flex h-9 w-9 items-center justify-center rounded-full text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-700 dark:hover:text-gray-300"
        >
          <CloseIcon className="h-5 w-5" />
        </button>
        <h2 className="text-lg font-semibold text-gray-800 dark:text-white/90">{title}</h2>
        {children}
      </div>
    </div>
  )
}
