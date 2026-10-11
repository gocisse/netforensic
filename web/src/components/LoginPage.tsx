import { useState } from 'react'
import type { FormEvent } from 'react'
import { useAuth } from '../auth/useAuth'
import { ApiError } from '../api'
import AuthLayout from '../layout/AuthLayout'
import Alert from './ui/Alert'
import Button from './ui/Button'
import Field from './ui/Field'

/** The sign-in screen, shown whenever there is no session. */
export default function LoginPage() {
  const { login, notice } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Something went wrong while signing in.')
      setBusy(false)
    }
  }

  return (
    <AuthLayout data-testid="login-page" title="Sign in" subtitle="Enter your username and password to use the analyzer.">
      <form onSubmit={submit} className="mt-6 space-y-6">
        {notice && (
          <Alert variant="warning" data-testid="login-notice">
            {notice}
          </Alert>
        )}

        <Field
          label="Username"
          id="username"
          name="username"
          autoComplete="username"
          autoFocus
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <Field
          label="Password"
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {error && (
          <p role="alert" data-testid="login-error" className="text-theme-sm text-error-600 dark:text-error-400">
            {error}
          </p>
        )}

        <Button type="submit" fullWidth loading={busy} disabled={username.trim() === '' || password === ''}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </AuthLayout>
  )
}
