import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { ApiClient } from '../api'
import { AuthContext } from './context'
import type { AuthContextValue } from './context'
import { TokenHolder } from './tokenHolder'
import { clearSession, loadSession, saveSession, sessionFromResponse } from './session'
import type { Session } from './session'

const SESSION_EXPIRED = 'Your session has expired. Please sign in again.'
const MAX_TIMEOUT = 2 ** 31 - 1 // setTimeout cannot wait longer

/** Holds the session (token, user, must-change flag) and the API client. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const [notice, setNotice] = useState<string | null>(null)
  // The API client reads the token at call time, so it always sees the latest session.
  const [tokenStore] = useState(() => new TokenHolder(session?.token ?? null))

  const update = useCallback(
    (next: Session | null) => {
      tokenStore.set(next?.token ?? null)
      if (next) saveSession(next)
      else clearSession()
      setSession(next)
    },
    [tokenStore],
  )

  const logout = useCallback(() => {
    update(null)
    setNotice(null)
  }, [update])

  const api = useMemo(
    () =>
      new ApiClient(
        () => tokenStore.get(),
        () => {
          update(null)
          setNotice(SESSION_EXPIRED)
        },
      ),
    [update, tokenStore],
  )

  const login = useCallback(
    async (username: string, password: string) => {
      const response = await api.login(username, password)
      setNotice(null)
      update(sessionFromResponse(response))
    },
    [api, update],
  )

  const changePassword = useCallback(
    async (oldPassword: string, newPassword: string) => {
      const response = await api.changePassword(oldPassword, newPassword)
      // Every older token stopped working with the old password: keep the new one.
      update(sessionFromResponse({ ...response, must_change_password: false }))
    },
    [api, update],
  )

  // Sign out when the token runs out, instead of waiting for a request to fail.
  useEffect(() => {
    if (!session) return
    const wait = Math.max(0, Math.min(session.expiresAt - Date.now(), MAX_TIMEOUT))
    const id = window.setTimeout(() => {
      update(null)
      setNotice(SESSION_EXPIRED)
    }, wait)
    return () => window.clearTimeout(id)
  }, [session, update])

  const value = useMemo<AuthContextValue>(
    () => ({ session, notice, api, login, changePassword, logout }),
    [session, notice, api, login, changePassword, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
