import type { ApiResult } from './types'

/** An error with a message that is fit to show to the user. */
export class ApiError extends Error {}

/**
 * Uploads a capture to the analysis endpoint and returns the parsed result.
 * Every failure is thrown as an ApiError with a readable message.
 */
export async function analyzeCapture(file: File, signal?: AbortSignal): Promise<ApiResult> {
  const form = new FormData()
  form.append('file', file)

  let response: Response
  try {
    response = await fetch('/api/analyze', { method: 'POST', body: form, signal })
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
    const message =
      typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string'
        ? body.error
        : `The server answered with HTTP ${response.status}.`
    throw new ApiError(capitalize(message))
  }
  if (typeof body !== 'object' || body === null || !('issues' in body)) {
    throw new ApiError('The server sent a response this page does not understand.')
  }
  return body as ApiResult
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
