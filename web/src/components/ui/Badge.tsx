import type { ReactNode } from 'react'

export type BadgeColor = 'primary' | 'success' | 'error' | 'warning' | 'info' | 'light' | 'purple' | 'pink' | 'teal'

const light: Record<BadgeColor, string> = {
  primary: 'bg-brand-50 dark:bg-brand-500/15 text-brand-600 dark:text-brand-400',
  success: 'bg-success-50 dark:bg-success-500/15 text-success-700 dark:text-success-400',
  error: 'bg-error-50 dark:bg-error-500/15 text-error-700 dark:text-error-400',
  warning: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400',
  info: 'bg-blue-light-50 dark:bg-blue-light-500/15 text-blue-light-700 dark:text-blue-light-400',
  light: 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300',
  purple: 'bg-violet-50 dark:bg-violet-500/15 text-violet-700 dark:text-violet-400',
  pink: 'bg-pink-50 dark:bg-pink-500/15 text-pink-700 dark:text-pink-400',
  teal: 'bg-teal-50 dark:bg-teal-500/15 text-teal-700 dark:text-teal-400',
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
