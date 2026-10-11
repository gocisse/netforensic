import type { ReactNode } from 'react'
import { useReveal } from '../../hooks/useReveal'
import Collapse from './Collapse'

/** Content that slides open and shut (200 ms) as `show` changes, and is not in the DOM while shut. */
export default function Reveal({ show, children, testId }: { show: boolean; children: ReactNode; testId?: string }) {
  const { mounted, open } = useReveal(show)
  if (!mounted) return null
  return (
    <Collapse open={open} testId={testId}>
      {children}
    </Collapse>
  )
}
