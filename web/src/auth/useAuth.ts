import { useContext } from 'react'
import { AuthContext } from './context'
import type { AuthContextValue } from './context'

/** The authentication state and actions. Must be used under AuthProvider. */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (value === null) throw new Error('useAuth must be used inside an AuthProvider')
  return value
}
