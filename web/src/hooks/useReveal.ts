import { useEffect, useState } from 'react'

/** How long a collapse takes, in milliseconds (the same as its CSS). */
export const COLLAPSE_MS = 200

/**
 * Tells a component with something that opens and closes when to keep it in
 * the DOM and when to show it open, so that it can animate both ways:
 * `mounted` is true from the moment `show` becomes true until the closing
 * animation has ended; `open` turns true one frame after the mount (so the
 * opening has something to animate from) and false as soon as `show` does.
 */
export function useReveal(show: boolean): { mounted: boolean; open: boolean } {
  const [lingering, setLingering] = useState(false)
  const [opened, setOpened] = useState(false)
  useEffect(() => {
    if (show) {
      const frame = requestAnimationFrame(() => {
        setLingering(true)
        setOpened(true)
      })
      return () => cancelAnimationFrame(frame)
    }
    const timer = setTimeout(() => {
      setOpened(false)
      setLingering(false)
    }, COLLAPSE_MS)
    return () => clearTimeout(timer)
  }, [show])
  return { mounted: show || lingering, open: show && opened }
}
