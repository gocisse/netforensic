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
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-gray-700">
        {label}
      </label>
      <input
        id={id}
        className={`h-11 w-full rounded-lg border bg-transparent px-4 py-2.5 text-sm text-gray-800 shadow-theme-xs placeholder:text-gray-400 focus:outline-hidden focus:ring-3 ${
          error
            ? 'border-error-300 focus:border-error-300 focus:ring-error-500/10'
            : 'border-gray-300 focus:border-brand-300 focus:ring-brand-500/10'
        } ${className}`}
        {...rest}
      />
      {hint && <p className="mt-1.5 text-theme-xs text-gray-500">{hint}</p>}
    </div>
  )
}
