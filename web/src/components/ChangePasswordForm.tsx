import { useState } from 'react'
import type { FormEvent } from 'react'
import { ApiError, SessionExpiredError } from '../api'
import { MAX_PASSWORD_BYTES, MIN_PASSWORD_LENGTH, validateNewPassword } from '../auth/password'
import { useAuth } from '../auth/useAuth'
import Button from './ui/Button'
import Field from './ui/Field'

interface Props {
  /** Called once the password has been changed. */
  onDone: () => void
  /** If given, a Cancel button is shown. The forced first-login screen has none. */
  onCancel?: () => void
}

/** The current-password, new-password and confirmation fields with their validation. */
export default function ChangePasswordForm({ onDone, onCancel }: Props) {
  const { changePassword } = useAuth()
  const [oldPassword, setOldPassword] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    const problem = validateNewPassword(oldPassword, next, confirm)
    if (problem) {
      setError(problem)
      return
    }
    setBusy(true)
    setError(null)
    try {
      await changePassword(oldPassword, next)
      onDone()
    } catch (err) {
      if (err instanceof SessionExpiredError) return // already signed out; the sign-in page explains
      setError(err instanceof ApiError ? err.message : 'Something went wrong while changing the password.')
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} data-testid="change-password-form" noValidate className="mt-5 space-y-5">
      <Field
        label="Current password"
        id="old-password"
        type="password"
        autoComplete="current-password"
        required
        value={oldPassword}
        onChange={(e) => setOldPassword(e.target.value)}
      />
      <Field
        label="New password"
        id="new-password"
        type="password"
        autoComplete="new-password"
        required
        value={next}
        onChange={(e) => setNext(e.target.value)}
        hint={`${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_BYTES} characters, different from the current one.`}
      />
      <Field
        label="Confirm new password"
        id="confirm-password"
        type="password"
        autoComplete="new-password"
        required
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
      />

      {error && (
        <p role="alert" data-testid="change-password-error" className="text-theme-sm text-error-600 dark:text-error-400">
          {error}
        </p>
      )}

      <div className="flex items-center justify-end gap-3">
        {onCancel && (
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        )}
        <Button type="submit" loading={busy} disabled={oldPassword === '' || next === '' || confirm === ''}>
          {busy ? 'Saving…' : 'Change password'}
        </Button>
      </div>
    </form>
  )
}
