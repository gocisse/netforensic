import { useContext } from 'react'
import { ToastContext } from './context'
import type { ToastApi } from './context'

/** The function that shows a toast. */
export function useToast(): ToastApi {
  const api = useContext(ToastContext)
  if (!api) throw new Error('useToast must be used inside ToastProvider')
  return api
}
