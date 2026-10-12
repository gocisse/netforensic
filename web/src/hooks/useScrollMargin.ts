import { useLayoutEffect, useState } from 'react'
import type { RefObject } from 'react'

/**
 * How far the top of an element is from the top of the document, kept current
 * while the page above it changes size. Window-scrolled virtual lists need it
 * to know where their rows start.
 */
export function useScrollMargin(ref: RefObject<HTMLElement | null>): number {
  const [margin, setMargin] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const measure = () => setMargin(Math.round(el.getBoundingClientRect().top + window.scrollY))
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(document.body)
    return () => ro.disconnect()
  }, [ref])
  return margin
}
