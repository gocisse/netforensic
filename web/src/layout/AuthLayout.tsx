import type { ReactNode } from 'react'
import Logo from '../components/Logo'

interface Props {
  title: string
  subtitle?: ReactNode
  children: ReactNode
  'data-testid'?: string
  /** Shown under the card. */
  footer?: ReactNode
}

/** A centered card on a soft background, for the sign-in and first-login screens. */
export default function AuthLayout({ title, subtitle, children, footer, ...rest }: Props) {
  return (
    <div data-testid={rest['data-testid']} className="flex min-h-screen flex-col items-center justify-center bg-gray-50 px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <Logo size="lg" />
          <p className="mt-2 text-theme-sm text-gray-500">Packet capture forensics</p>
        </div>
        <div className="rounded-2xl border border-gray-200 bg-white p-6 shadow-theme-sm sm:p-8">
          <h1 className="text-title-sm font-semibold text-gray-800 sm:text-2xl">{title}</h1>
          {subtitle && <p className="mt-2 text-theme-sm text-gray-500">{subtitle}</p>}
          {children}
        </div>
        {footer && <div className="mt-4 text-center text-theme-sm text-gray-500">{footer}</div>}
      </div>
    </div>
  )
}
