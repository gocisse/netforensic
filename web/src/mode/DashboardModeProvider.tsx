import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { DashboardModeContext, MODE_KEY } from './context'
import type { DashboardMode } from './context'

function loadMode(): DashboardMode {
  try {
    const saved = localStorage.getItem(MODE_KEY)
    if (saved === 'junior' || saved === 'senior') return saved
  } catch {
    // storage blocked: use the default
  }
  return 'senior'
}

/** Holds the dashboard mode: Senior unless the user chose Junior, and remembered across visits. */
export function DashboardModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<DashboardMode>(loadMode)

  const setMode = useCallback((next: DashboardMode) => {
    setModeState(next)
    try {
      localStorage.setItem(MODE_KEY, next)
    } catch {
      // the choice then lasts until the page is closed
    }
  }, [])
  const toggleMode = useCallback(() => setMode(mode === 'junior' ? 'senior' : 'junior'), [mode, setMode])

  // another tab changed the choice
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === MODE_KEY && (e.newValue === 'junior' || e.newValue === 'senior')) setModeState(e.newValue)
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const value = useMemo(() => ({ mode, setMode, toggleMode }), [mode, setMode, toggleMode])
  return <DashboardModeContext.Provider value={value}>{children}</DashboardModeContext.Provider>
}
