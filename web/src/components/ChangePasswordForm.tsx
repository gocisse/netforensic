import { useState } from 'react'
import type { FormEvent } from 'react'
import { ApiError, SessionExpiredError } from '../api'
import { MAX_PASSWORD_BYTES, MIN_PASSWORD_LENGTH, validateNewPassword } from '../auth/password'
import { useAuth } from '../auth/useAuth'

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

  const input =
    'mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500'
  return (
    <form onSubmit={submit} data-testid="change-password-form" noValidate>
      <label className="mt-4 block text-sm font-medium text-slate-700" htmlFor="old-password">
        Current password
      </label>
      <input id="old-password" type="password" autoComplete="current-password" required value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} className={input} />

      <label className="mt-4 block text-sm font-medium text-slate-700" htmlFor="new-password">
        New password
      </label>
      <input id="new-password" type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} className={input} />
      <p className="mt-1 text-xs text-slate-500">
        {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_BYTES} characters, different from the current one.
      </p>

      <label className="mt-4 block text-sm font-medium text-slate-700" htmlFor="confirm-password">
        Confirm new password
      </label>
      <input id="confirm-password" type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} className={input} />

      {error && (
        <p role="alert" data-testid="change-password-error" className="mt-3 text-sm text-red-600">
          {error}
        </p>
      )}

      <div className="mt-5 flex items-center justify-end gap-3">
        {onCancel && (
          <button type="button" onClick={onCancel} disabled={busy} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100">
            Cancel
          </button>
        )}
        <button
          type="submit"
          disabled={busy || oldPassword === '' || next === '' || confirm === ''}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {busy && <span aria-hidden="true" className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />}
          {busy ? 'Saving…' : 'Change password'}
        </button>
      </div>
    </form>
  )
}
