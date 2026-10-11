import type { ReactNode } from 'react'

interface Props {
  label: string
  value: ReactNode
  /** A small line under the value. */
  hint?: ReactNode
  icon?: ReactNode
  /** Tailwind classes that color the icon tile. */
  iconTone?: string
  'data-testid'?: string
}

/** A metric tile: a label, a large value, and an optional icon and hint. */
export default function StatCard({ label, value, hint, icon, iconTone = 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white/90', ...rest }: Props) {
  return (
    <div data-testid={rest['data-testid']} className="rounded-2xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-5 shadow-theme-xs md:p-6">
      {icon && <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${iconTone}`}>{icon}</div>}
      <div className={icon ? 'mt-5' : ''}>
        <span className="text-sm text-gray-500 dark:text-gray-400">{label}</span>
        <h4 className="mt-2 text-title-sm font-bold text-gray-800 dark:text-white/90">{value}</h4>
        {hint && <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">{hint}</div>}
      </div>
    </div>
  )
}
