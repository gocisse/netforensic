import type { ReactNode } from 'react'
import { AlertIcon, CheckCircleIcon, ErrorIcon, InfoIcon } from '../../icons'

export type AlertVariant = 'success' | 'error' | 'warning' | 'info'

const styles: Record<AlertVariant, { box: string; icon: string }> = {
  success: { box: 'border-success-500 bg-success-50', icon: 'text-success-500' },
  error: { box: 'border-error-500 bg-error-50', icon: 'text-error-500' },
  warning: { box: 'border-warning-500 bg-warning-50', icon: 'text-warning-500' },
  info: { box: 'border-blue-light-500 bg-blue-light-50', icon: 'text-blue-light-500' },
}

const icons = { success: CheckCircleIcon, error: ErrorIcon, warning: AlertIcon, info: InfoIcon }

interface Props {
  variant: AlertVariant
  title?: string
  children: ReactNode
  /** Use role="alert" for errors that need announcing, role="status" otherwise. */
  role?: 'alert' | 'status'
  className?: string
  'data-testid'?: string
}

/** A banner for a message about the page or the capture. */
export default function Alert({ variant, title, children, role = 'status', className = '', ...rest }: Props) {
  const Icon = icons[variant]
  return (
    <div role={role} className={`rounded-xl border p-4 ${styles[variant].box} ${className}`} data-testid={rest['data-testid']}>
      <div className="flex items-start gap-3">
        <Icon className={`-mt-0.5 h-6 w-6 flex-none ${styles[variant].icon}`} />
        <div className="min-w-0">
          {title && <h4 className="mb-1 text-sm font-semibold text-gray-800">{title}</h4>}
          <div className="text-sm text-gray-600">{children}</div>
        </div>
      </div>
    </div>
  )
}
