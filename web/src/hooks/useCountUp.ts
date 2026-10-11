import { useEffect, useRef, useState } from 'react'

/** Whether the system asks for less motion. */
export function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

/**
 * A number that counts from 0 (on the first render) or from where it is (when
 * `target` changes) to `target` in `ms` milliseconds, easing out. With
 * reduced motion it is `target` at once. It always ends on exactly `target`.
 */
export function useCountUp(target: number, ms = 1000): number {
  const [reduced] = useState(prefersReducedMotion)
  const [shown, setShown] = useState(0)
  const latest = useRef(0)

  useEffect(() => {
    if (reduced) return
    const from = latest.current
    const start = performance.now()
    let frame = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ms)
      const eased = 1 - Math.pow(1 - t, 3)
      latest.current = t === 1 ? target : Math.round(from + (target - from) * eased)
      setShown(latest.current)
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target, ms, reduced])

  return reduced ? target : shown
}
