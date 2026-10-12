import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { CloseIcon } from '../icons'

interface Props {
  title: string
  onClose: () => void
  children: ReactNode
  /** A wide dialog that scrolls inside the window, for content that does not fit a form's width. */
  wide?: boolean
}

/** A centered dialog over a dimmed backdrop. Escape and a click outside close it. */
export default function Modal({ title, onClose, children, wide = false }: Props) {
  const dialog = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  // The page behind does not scroll while the dialog is open.
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [])

  useEffect(() => {
    dialog.current?.querySelector<HTMLElement>('input, button')?.focus()
  }, [])

  // Rendered in the body so that no animated or stacked ancestor confines the backdrop to part of the page.
  return createPortal(
    <div
      className={`fixed inset-0 z-99999 flex justify-center bg-gray-900/50 px-4 backdrop-blur-[2px] ${wide ? 'items-start overflow-y-auto py-8' : 'items-center'}`}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div ref={dialog} role="dialog" aria-modal="true" aria-label={title} className={`relative w-full ${wide ? 'max-w-3xl' : 'max-w-md'} animate-dialog-in rounded-2xl bg-white dark:bg-gray-900 p-6 shadow-theme-xl sm:p-8`}>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="absolute right-4 top-4 flex h-9 w-9 items-center justify-center rounded-full text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 hover:text-gray-700 dark:hover:text-gray-300"
        >
          <CloseIcon className="h-5 w-5" />
        </button>
        <h2 className="text-lg font-semibold text-gray-800 dark:text-white/90">{title}</h2>
        {children}
      </div>
    </div>,
    document.body,
  )
}
