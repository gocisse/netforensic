import type { ReactNode } from 'react'

export type BadgeColor = 'primary' | 'success' | 'error' | 'warning' | 'info' | 'light' | 'purple' | 'pink' | 'teal'

const light: Record<BadgeColor, string> = {
  primary: 'bg-brand-50 text-brand-600',
  success: 'bg-success-50 text-success-700',
  error: 'bg-error-50 text-error-700',
  warning: 'bg-warning-50 text-warning-700',
  info: 'bg-blue-light-50 text-blue-light-700',
  light: 'bg-gray-100 text-gray-700',
  purple: 'bg-violet-50 text-violet-700',
  pink: 'bg-pink-50 text-pink-700',
  teal: 'bg-teal-50 text-teal-700',
}

const solid: Record<BadgeColor, string> = {
  primary: 'bg-brand-500 text-white',
  success: 'bg-success-500 text-white',
  error: 'bg-error-500 text-white',
  warning: 'bg-warning-500 text-white',
  info: 'bg-blue-light-500 text-white',
  light: 'bg-gray-400 text-white',
  purple: 'bg-violet-500 text-white',
  pink: 'bg-pink-500 text-white',
  teal: 'bg-teal-500 text-white',
}

interface Props {
  color?: BadgeColor
  variant?: 'light' | 'solid'
  children: ReactNode
  className?: string
}

/** A small pill label. */
export default function Badge({ color = 'primary', variant = 'light', children, className = '' }: Props) {
  const palette = variant === 'solid' ? solid : light
  return (
    <span className={`inline-flex items-center justify-center gap-1 rounded-full px-2.5 py-0.5 text-theme-xs font-medium ${palette[color]} ${className}`}>
      {children}
    </span>
  )
}
