import { createContext } from 'react'

export type ToastKind = 'success' | 'info' | 'error'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

export interface ToastApi {
  /** Shows a message in the bottom-right corner; it goes away by itself after 3 seconds. */
  show: (message: string, kind?: ToastKind) => void
}

/** How long a toast stays, in milliseconds. */
export const TOAST_MS = 3000

export const ToastContext = createContext<ToastApi | null>(null)
