import type { ReactNode } from 'react'

interface CardProps {
  children: ReactNode
  className?: string
  'data-testid'?: string
}

/** A white panel with a border and a soft shadow. */
export function Card({ children, className = '', ...rest }: CardProps) {
  return (
    <section data-testid={rest['data-testid']} className={`rounded-2xl border border-gray-200 bg-white shadow-theme-xs ${className}`}>
      {children}
    </section>
  )
}

interface HeaderProps {
  title: string
  description?: ReactNode
  action?: ReactNode
}

/** The title row of a card, with an optional description and action. */
export function CardHeader({ title, description, action }: HeaderProps) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 px-5 py-4 sm:px-6 sm:py-5">
      <div className="min-w-0">
        <h3 className="text-base font-medium text-gray-800">{title}</h3>
        {description && <p className="mt-1 text-sm text-gray-500">{description}</p>}
      </div>
      {action}
    </div>
  )
}

/** The padded body of a card. */
export function CardBody({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`border-t border-gray-100 p-5 sm:p-6 ${className}`}>{children}</div>
}
