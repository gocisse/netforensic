import { useContext } from 'react'
import { DashboardModeContext } from './context'
import type { DashboardModeState } from './context'

/** The dashboard mode and how to change it. */
export function useDashboardMode(): DashboardModeState {
  const state = useContext(DashboardModeContext)
  if (!state) throw new Error('useDashboardMode must be used inside <DashboardModeProvider>')
  return state
}
