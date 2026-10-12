import { useEffect, useState } from 'react'

/** Items drawn at first, and added per tick, so that a long list does not freeze the page while it is drawn. */
const FIRST = 12
const STEP = 24
/** The most that is drawn without being asked; beyond that, `more` draws MORE at a time. */
const AUTO = 300
const MORE = 100

export interface Drawn {
  /** How many items to draw now. */
  count: number
  /** Whether more are being drawn on their own. */
  drawing: boolean
  /** How many are left out until `more` is called. */
  waiting: number
  more: () => void
}

/**
 * How much of a long list to draw: the first few at once, the rest a step at a
 * time on later ticks up to 300 items, then on request. A new `list` (a new
 * array) starts again from the first step.
 */
export function useDrawn(list: readonly unknown[]): Drawn {
  const [drawn, setDrawn] = useState<{ of: readonly unknown[]; count: number }>({ of: list, count: FIRST })
  const count = drawn.of === list ? drawn.count : FIRST
  const target = Math.min(list.length, AUTO)
  useEffect(() => {
    if (count >= target) return
    const t = setTimeout(() => setDrawn({ of: list, count: Math.min(count + STEP, target) }), 0)
    return () => clearTimeout(t)
  }, [count, target, list])
  return {
    count,
    drawing: count < target,
    waiting: Math.max(0, list.length - count),
    more: () => setDrawn({ of: list, count: Math.min(count + MORE, list.length) }),
  }
}
