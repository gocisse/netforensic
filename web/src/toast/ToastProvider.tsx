import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { CloseIcon } from '../icons'
import { TOAST_MS, ToastContext } from './context'
import type { Toast, ToastKind } from './context'

const TONE: Record<ToastKind, string> = {
  success: 'border-success-300 dark:border-success-500/40 bg-success-50 dark:bg-gray-900 text-success-800 dark:text-success-300',
  info: 'border-blue-light-300 dark:border-blue-light-500/40 bg-blue-light-50 dark:bg-gray-900 text-blue-light-900 dark:text-blue-light-300',
  error: 'border-error-300 dark:border-error-500/40 bg-error-50 dark:bg-gray-900 text-error-800 dark:text-error-300',
}

/**
 * Shows short messages in the bottom-right corner, stacked, each gone after
 * three seconds (or when closed). The stack is a polite live region, so a
 * screen reader announces a toast without interrupting.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const next = useRef(1)
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>())

  const dismiss = useCallback((id: number) => {
    const t = timers.current.get(id)
    if (t) clearTimeout(t)
    timers.current.delete(id)
    setToasts((all) => all.filter((x) => x.id !== id))
  }, [])

  const show = useCallback(
    (message: string, kind: ToastKind = 'success') => {
      const id = next.current++
      setToasts((all) => [...all, { id, kind, message }])
      timers.current.set(id, setTimeout(() => dismiss(id), TOAST_MS))
    },
    [dismiss],
  )

  useEffect(() => {
    const pending = timers.current
    return () => pending.forEach((t) => clearTimeout(t))
  }, [])

  const api = useMemo(() => ({ show }), [show])
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        role="region"
        aria-label="Notifications"
        aria-live="polite"
        data-testid="toast-stack"
        className="pointer-events-none fixed bottom-4 right-4 z-[100000] flex w-[calc(100%-2rem)] max-w-sm flex-col gap-2"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            data-testid="toast"
            data-kind={t.kind}
            className={`pointer-events-auto flex animate-toast-in items-start gap-3 rounded-xl border px-4 py-3 text-theme-sm font-medium shadow-theme-lg ${TONE[t.kind]}`}
          >
            <span className="min-w-0 flex-1 break-words">{t.message}</span>
            <button type="button" onClick={() => dismiss(t.id)} aria-label="Dismiss" className="flex-none rounded p-1 opacity-70 hover:opacity-100">
              <CloseIcon className="h-4 w-4" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
