import type { ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react'

/** The table primitives, styled like the admin template's data tables. */
export function Table({ children }: { children: ReactNode }) {
  return <table className="min-w-full text-left">{children}</table>
}

export function TableHeader({ children }: { children: ReactNode }) {
  return <thead className="border-y border-gray-100 bg-gray-50">{children}</thead>
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-gray-100">{children}</tbody>
}

export function TableRow({ children, className = '', ...rest }: { children: ReactNode; className?: string } & Record<`data-${string}`, string | undefined>) {
  return (
    <tr className={className} {...rest}>
      {children}
    </tr>
  )
}

/** A header cell. */
export function TableHead({ children, className = '', ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={`px-4 py-3 text-theme-xs font-medium uppercase tracking-wide text-gray-500 ${className}`} {...rest}>
      {children}
    </th>
  )
}

/** A body cell. */
export function TableCell({ children, className = '', ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={`px-4 py-3 text-theme-sm text-gray-600 ${className}`} {...rest}>
      {children}
    </td>
  )
}
