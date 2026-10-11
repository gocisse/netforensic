import { createContext } from 'react'

/** Who the dashboard is written for: Junior explains in plain words, Senior shows the technical detail. */
export type DashboardMode = 'junior' | 'senior'

export interface DashboardModeState {
  mode: DashboardMode
  setMode: (mode: DashboardMode) => void
  toggleMode: () => void
}

export const DashboardModeContext = createContext<DashboardModeState | null>(null)

/** The localStorage key of the saved choice. */
export const MODE_KEY = 'netforensic-mode'
