import type { ApiResult } from './types'

/** An error with a message that is fit to show to the user. */
export class ApiError extends Error {
  readonly status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.status = status
  }
}

/** The server no longer accepts the session's token. */
export class SessionExpiredError extends ApiError {}

/** What the login and change-password endpoints answer with. */
export interface TokenResponse {
  token: string
  expires_at: string
  username: string
  must_change_password: boolean
}

interface RequestOptions {
  /** Attach the session's token (default). Login is the one call that does not. */
  auth?: boolean
  signal?: AbortSignal
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/**
 * Talks to the netforensic API. It attaches the session's bearer token to
 * every call, and when the server rejects that token it tells the owner of the
 * session (so the app can sign the user out) and throws SessionExpiredError.
 */
export class ApiClient {
  private readonly getToken: () => string | null
  private readonly onSessionExpired: () => void

  constructor(getToken: () => string | null, onSessionExpired: () => void) {
    this.getToken = getToken
    this.onSessionExpired = onSessionExpired
  }

  /** Sends a request and returns the parsed JSON body of a successful answer. */
  async request<T>(path: string, init: RequestInit = {}, options: RequestOptions = {}): Promise<T> {
    const headers = new Headers(init.headers)
    const token = options.auth === false ? null : this.getToken()
    if (token) headers.set('Authorization', `Bearer ${token}`)

    let response: Response
    try {
      response = await fetch(path, { ...init, headers, signal: options.signal })
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') throw err
      throw new ApiError('Could not reach the analysis server. Is it still running?')
    }

    let body: unknown
    try {
      body = await response.json()
    } catch {
      body = undefined
    }

    if (!response.ok) {
      // A 401 that carries a WWW-Authenticate header means the token was
      // refused. Without the header it is the answer to wrong credentials
      // (a wrong login or a wrong current password), not an expired session.
      if (response.status === 401 && response.headers.has('WWW-Authenticate')) {
        this.onSessionExpired()
        throw new SessionExpiredError('Your session has expired. Please sign in again.', 401)
      }
      const message =
        typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string'
          ? body.error
          : `The server answered with HTTP ${response.status}.`
      throw new ApiError(capitalize(message), response.status)
    }
    return body as T
  }

  /** POSTs a JSON body. */
  postJSON<T>(path: string, payload: unknown, options: RequestOptions = {}): Promise<T> {
    return this.request<T>(
      path,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
      options,
    )
  }

  /** Signs in. The one call that is made without a token. */
  login(username: string, password: string): Promise<TokenResponse> {
    return this.postJSON<TokenResponse>('/api/login', { username, password }, { auth: false })
  }

  /** Changes the password; the answer holds a fresh token. */
  changePassword(oldPassword: string, newPassword: string): Promise<TokenResponse> {
    return this.postJSON<TokenResponse>('/api/change-password', { old_password: oldPassword, new_password: newPassword })
  }

  /** Uploads a capture for analysis. */
  async analyzeCapture(file: File, signal?: AbortSignal): Promise<ApiResult> {
    const form = new FormData()
    form.append('file', file)
    const body = await this.request<unknown>('/api/analyze', { method: 'POST', body: form }, { signal })
    if (typeof body !== 'object' || body === null || !('issues' in body)) {
      throw new ApiError('The server sent a response this page does not understand.')
    }
    return body as ApiResult
  }
}
