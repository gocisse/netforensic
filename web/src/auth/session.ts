/** The signed-in user, as kept in the browser for the life of the tab. */
export interface Session {
  token: string
  username: string
  /** When the token stops working, in milliseconds since the epoch. */
  expiresAt: number
  /** True until the default password has been changed. */
  mustChangePassword: boolean
}

const KEY = 'netforensic.session'

function isSession(v: unknown): v is Session {
  if (typeof v !== 'object' || v === null) return false
  const s = v as Record<string, unknown>
  return (
    typeof s.token === 'string' &&
    s.token !== '' &&
    typeof s.username === 'string' &&
    typeof s.expiresAt === 'number' &&
    typeof s.mustChangePassword === 'boolean'
  )
}

/**
 * Reads the session kept by saveSession. A session that is malformed or past
 * its expiry is removed and treated as absent. sessionStorage is used on
 * purpose: the token disappears when the tab is closed.
 */
export function loadSession(now: number = Date.now()): Session | null {
  let raw: string | null
  try {
    raw = sessionStorage.getItem(KEY)
  } catch {
    return null // storage unavailable: behave as signed out
  }
  if (raw === null) return null

  try {
    const parsed: unknown = JSON.parse(raw)
    if (isSession(parsed) && parsed.expiresAt > now) return parsed
  } catch {
    // not JSON: fall through and discard it
  }
  clearSession()
  return null
}

export function saveSession(session: Session): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(session))
  } catch {
    // the session then lasts until the page is reloaded
  }
}

export function clearSession(): void {
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // nothing to clear
  }
}

/** Builds a session from the answer of the login or change-password endpoint. */
export function sessionFromResponse(r: { token: string; expires_at: string; username: string; must_change_password: boolean }): Session {
  const expiresAt = Date.parse(r.expires_at)
  return {
    token: r.token,
    username: r.username,
    expiresAt: Number.isNaN(expiresAt) ? Date.now() + 60 * 60 * 1000 : expiresAt,
    mustChangePassword: r.must_change_password,
  }
}
