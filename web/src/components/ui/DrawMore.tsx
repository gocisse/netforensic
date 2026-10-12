import type { Drawn } from '../../hooks/useDrawn'
import Button from './Button'

/** What follows a partly drawn list: a note while it is being drawn, then a button for the rest. */
export default function DrawMore({ drawn, noun = 'issues' }: { drawn: Drawn; noun?: string }) {
  if (drawn.drawing) {
    return (
      <p className="text-center text-theme-sm text-gray-500 dark:text-gray-400" role="status" data-testid="issues-drawing">
        Drawing the remaining {drawn.waiting.toLocaleString()} {noun}…
      </p>
    )
  }
  if (drawn.waiting === 0) return null
  return (
    <div className="text-center">
      <Button variant="outline" size="sm" data-testid="issues-show-more" onClick={drawn.more}>
        Show {Math.min(100, drawn.waiting).toLocaleString()} more ({drawn.waiting.toLocaleString()} not shown)
      </Button>
    </div>
  )
}
