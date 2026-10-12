import type { HTMLAttributes, ReactNode, Ref, TdHTMLAttributes, ThHTMLAttributes } from 'react'

/** The table primitives, styled like the admin template's data tables. */
export function Table({ children }: { children: ReactNode }) {
  return <table className="min-w-full text-left">{children}</table>
}

export function TableHeader({ children }: { children: ReactNode }) {
  return <thead className="border-y border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/60">{children}</thead>
}

export function TableBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-gray-100 dark:divide-gray-800 dark:[&>tr:nth-child(even)]:bg-white/[0.02]">{children}</tbody>
}

export function TableRow({ children, className = '', ...rest }: HTMLAttributes<HTMLTableRowElement> & { ref?: Ref<HTMLTableRowElement> } & Record<`data-${string}`, string | number | undefined>) {
  return (
    <tr className={`transition-colors duration-150 hover:bg-gray-50 dark:hover:bg-white/[0.04] ${className}`} {...rest}>
      {children}
    </tr>
  )
}

/** A header cell. */
export function TableHead({ children, className = '', ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th className={`px-4 py-3 text-theme-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400 ${className}`} {...rest}>
      {children}
    </th>
  )
}

/** A body cell. */
export function TableCell({ children, className = '', ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={`px-4 py-3 text-theme-sm text-gray-600 dark:text-gray-400 ${className}`} {...rest}>
      {children}
    </td>
  )
}
