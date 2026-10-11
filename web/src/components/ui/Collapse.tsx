import type { ReactNode } from 'react'

/**
 * Shows or hides its children with a smooth height change (200 ms ease-in-out).
 * Closed content is `inert`, so it cannot be focused or read while hidden,
 * but it stays mounted so that the animation can run both ways.
 */
export default function Collapse({ open, children, testId }: { open: boolean; children: ReactNode; testId?: string }) {
  return (
    <div
      data-testid={testId}
      data-open={open}
      className={`grid transition-[grid-template-rows,opacity] duration-200 ease-in-out ${open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`}
      inert={!open}
    >
      <div className="min-h-0 overflow-hidden">{children}</div>
    </div>
  )
}
