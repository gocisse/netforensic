export const MIN_PASSWORD_LENGTH = 6
export const MAX_PASSWORD_BYTES = 72 // bcrypt ignores everything after 72 bytes

/** Checks a new password the way the server will, so the user gets the answer at once. */
export function validateNewPassword(oldPassword: string, next: string, confirm: string): string | null {
  if (next.length < MIN_PASSWORD_LENGTH) return `The new password must be at least ${MIN_PASSWORD_LENGTH} characters.`
  if (new TextEncoder().encode(next).length > MAX_PASSWORD_BYTES) return `The new password must be at most ${MAX_PASSWORD_BYTES} bytes.`
  if (next === oldPassword) return 'The new password must differ from the current one.'
  if (next !== confirm) return 'The new passwords do not match.'
  return null
}
