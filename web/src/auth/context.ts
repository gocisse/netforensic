import { createContext } from 'react'
import type { ApiClient } from '../api'
import type { Session } from './session'

export interface AuthContextValue {
  /** The signed-in user, or null. */
  session: Session | null
  /** Why the user was signed out, if it was not their own doing. */
  notice: string | null
  /** The API client of this session: it attaches the token to every call. */
  api: ApiClient
  login: (username: string, password: string) => Promise<void>
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
