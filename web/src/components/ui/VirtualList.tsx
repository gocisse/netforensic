import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'
import type { Key, ReactNode } from 'react'
import { useScrollMargin } from '../../hooks/useScrollMargin'

/** How many rows are drawn beyond the visible ones, on each side. */
const OVERSCAN = 8

export interface Props<T> {
  items: readonly T[]
  /** A stable key for an item, so that measured heights survive a change of the list. */
  getKey: (item: T) => Key
  /** A guess of an item's height in px before it is drawn; it is measured once it is. */
  estimate: (item: T) => number
  /** The space below each row, in px. */
  gap?: number
  render: (item: T) => ReactNode
  testId?: string
}

/**
 * A list that scrolls with the page and draws only the rows in view plus a
 * few more on each side, so a list of any length costs the same. Rows may
 * differ in height and change it (an expanded card): each is measured.
 */
export default function VirtualList<T>({ items, getKey, estimate, gap = 0, render, testId }: Props<T>) {
  const box = useRef<HTMLDivElement>(null)
  const scrollMargin = useScrollMargin(box)
  // The React Compiler is not used here, so the library's un-memoizable functions are fine.
  // oxlint-disable-next-line react/incompatible-library
  const virtualizer = useWindowVirtualizer({
    count: items.length,
    estimateSize: (i) => estimate(items[i]) + gap,
    getItemKey: (i) => getKey(items[i]),
    overscan: OVERSCAN,
    scrollMargin,
  })

  return (
    <div ref={box} data-testid={testId} data-total={items.length} style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
      {virtualizer.getVirtualItems().map((row) => (
        <div
          key={row.key}
          data-index={row.index}
          ref={virtualizer.measureElement}
          style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${row.start - scrollMargin}px)`, paddingBottom: gap }}
        >
          {render(items[row.index])}
        </div>
      ))}
    </div>
  )
}
