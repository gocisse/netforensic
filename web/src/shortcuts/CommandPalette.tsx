import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { filterItems, GROUP_ORDER } from './search'
import type { PaletteItem } from './search'

interface Props {
  items: PaletteItem[]
  onChoose: (item: PaletteItem) => void
  onClose: () => void
}

/**
 * The command palette (Ctrl/Cmd+K): a search box over the pages, the actions
 * and the issues of the analysis. Arrow keys move, Enter chooses, Escape
 * closes. It is a combobox with a listbox, so a screen reader follows the
 * highlighted result.
 */
export default function CommandPalette({ items, onChoose, onClose }: Props) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const list = useRef<HTMLUListElement>(null)
  const listId = useId()

  const results = useMemo(() => filterItems(items, query), [items, query])
  const current = Math.min(active, Math.max(0, results.length - 1))

  useEffect(() => input.current?.focus(), [])
  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [current, results])

  const onKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setActive(results.length === 0 ? 0 : (current + 1) % results.length)
        break
      case 'ArrowUp':
        e.preventDefault()
        setActive(results.length === 0 ? 0 : (current - 1 + results.length) % results.length)
        break
      case 'Enter':
        e.preventDefault()
        if (results[current]) onChoose(results[current])
        break
      case 'Escape':
        e.preventDefault()
        e.stopPropagation()
        onClose()
        break
    }
  }

  return (
    <div
      className="fixed inset-0 z-99999 flex items-start justify-center bg-gray-900/50 px-4 pt-[12vh] backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        data-testid="command-palette"
        onKeyDown={onKeyDown}
        className="w-full max-w-xl animate-dialog-in overflow-hidden rounded-2xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-theme-xl"
      >
        <input
          ref={input}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={results[current] ? `${listId}-${current}` : undefined}
          aria-label="Search issues, pages and actions"
          data-testid="palette-input"
          type="text"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setActive(0)
          }}
          placeholder="Search issues, or jump to a page…"
          autoComplete="off"
          spellCheck={false}
          className="h-14 w-full border-b border-gray-200 dark:border-gray-800 bg-transparent px-4 text-base text-gray-800 dark:text-white/90 placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:outline-hidden"
        />
        <ul ref={list} id={listId} role="listbox" aria-label="Results" className="max-h-[50vh] overflow-y-auto p-2" data-testid="palette-results">
          {results.length === 0 && (
            <li role="presentation" className="px-4 py-8 text-center text-theme-sm text-gray-600 dark:text-gray-400" data-testid="palette-empty">
              Nothing matches “{query}”.
            </li>
          )}
          {results.map((item, i) => {
            const heading = i === 0 || results[i - 1].group !== item.group
            return (
              <li key={item.id} role="presentation">
                {heading && (
                  <p className="px-3 pb-1 pt-3 text-theme-xs font-semibold uppercase tracking-wide text-gray-600 dark:text-gray-400" role="presentation">
                    {GROUP_ORDER.includes(item.group) ? item.group : ''}
                  </p>
                )}
                <div
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={i === current}
                  data-testid="palette-item"
                  data-id={item.id}
                  onMouseMove={() => setActive(i)}
                  onClick={() => onChoose(item)}
                  className={`flex cursor-pointer items-center justify-between gap-3 rounded-lg px-3 py-2 text-theme-sm transition-colors ${
                    i === current ? 'bg-brand-50 dark:bg-brand-500/15 text-brand-700 dark:text-brand-300' : 'text-gray-700 dark:text-gray-300'
                  }`}
                >
                  <span className="min-w-0 truncate">{item.label}</span>
                  {item.hint && <span className="flex-none rounded bg-gray-100 dark:bg-gray-800 px-2 py-1 font-mono text-theme-xs text-gray-700 dark:text-gray-300">{item.hint}</span>}
                </div>
              </li>
            )
          })}
        </ul>
        <p className="border-t border-gray-200 dark:border-gray-800 px-4 py-2 text-theme-xs text-gray-600 dark:text-gray-400">↑↓ to move · Enter to choose · Esc to close</p>
      </div>
    </div>
  )
}
