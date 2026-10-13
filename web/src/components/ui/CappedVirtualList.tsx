import { useMemo, useState } from 'react'
import { LIST_MAX as MAX, LIST_STEP as STEP } from '../../listCap'
import type { Props as ListProps } from './VirtualList'
import Button from './Button'
import VirtualList from './VirtualList'

/**
 * A virtual list of the first rows of a very long list: 5,000 at first, and a
 * button for 5,000 more up to 50,000. The rows are ordered so that the ones
 * that matter come first, which is why cutting the end off is no loss.
 */
export default function CappedVirtualList<T>({ items, noun = 'issues', counts, ...rest }: ListProps<T> & { noun?: string; counts?: (item: T) => boolean }) {
  const [limit, setLimit] = useState(STEP)
  const shown = Math.min(limit, MAX)
  const visible = useMemo(() => (items.length > shown ? items.slice(0, shown) : items), [items, shown])
  // What the note counts: every row, or only those that `counts` says are items (not headings).
  const total = useMemo(() => (counts ? items.reduce((n, i) => n + (counts(i) ? 1 : 0), 0) : items.length), [items, counts])
  const shownCount = useMemo(() => (counts ? visible.reduce((n, i) => n + (counts(i) ? 1 : 0), 0) : visible.length), [visible, counts])
  return (
    <>
      <VirtualList items={visible} {...rest} />
      {items.length > shown && (
        <div className="mt-4 space-y-3 text-center" data-testid="list-capped">
          <p className="text-theme-sm text-gray-600 dark:text-gray-400">
            Showing the first {shownCount.toLocaleString()} of {total.toLocaleString()} {noun}, the worst first. {shown >= MAX ? 'Narrow the list with the filters, or export all of it as CSV.' : ''}
          </p>
          {shown < MAX && (
            <Button variant="outline" size="sm" data-testid="list-show-more" onClick={() => setLimit((l) => Math.min(l + STEP, MAX))}>
              Show {Math.min(STEP, total - shownCount, MAX - shown).toLocaleString()} more
            </Button>
          )}
        </div>
      )}
    </>
  )
}
