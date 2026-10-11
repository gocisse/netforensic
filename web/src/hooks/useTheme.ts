import { useCallback, useState } from 'react'

export type Theme = 'light' | 'dark'

/** The localStorage key; index.html reads it too, to theme the page before first paint. */
export const THEME_KEY = 'netforensic-theme'

/** The saved preference, else the system's, else light. */
function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    // storage blocked: fall through to the system preference
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function apply(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
}

/** The current theme and a function that flips it, persisting the choice. */
export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  const [theme, setTheme] = useState<Theme>(() => {
    const t = initialTheme()
    apply(t)
    return t
  })

  const toggleTheme = useCallback(() => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark'
    apply(next)
    try {
      localStorage.setItem(THEME_KEY, next)
    } catch {
      // the theme still changes for this visit
    }
    setTheme(next)
  }, [theme])

  return { theme, toggleTheme }
}
