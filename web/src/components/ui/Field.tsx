import type { InputHTMLAttributes, ReactNode } from 'react'

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  id: string
  hint?: ReactNode
  error?: boolean
}

/** A labelled text input in the admin theme. */
export default function Field({ label, id, hint, error = false, className = '', ...rest }: Props) {
  return (
    <div>
      <label htmlFor={id} className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
        {label}
      </label>
      <input
        id={id}
        className={`h-11 w-full rounded-lg border bg-transparent dark:bg-gray-900 px-4 py-3 text-sm text-gray-800 dark:text-white/90 shadow-theme-xs placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:outline-hidden focus:ring-3 ${
          error
            ? 'border-error-300 dark:border-error-500/50 focus:border-error-300 dark:focus:border-error-500/50 focus:ring-error-500/10'
            : 'border-gray-300 dark:border-gray-700 focus:border-brand-300 dark:focus:border-brand-500/60 focus:ring-brand-500/10'
        } ${className}`}
        {...rest}
      />
      {hint && <p className="mt-2 text-theme-xs text-gray-500 dark:text-gray-400">{hint}</p>}
    </div>
  )
}
