import { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fromParams, isActive, NO_FILTERS, PARAM_NAMES, parseFilters, tidy, toParams, validate } from './model'
import type { FilterErrors, FilterState, ParsedFilters } from './model'

export interface Filters {
  /** What is typed in the panel, not yet applied. */
  draft: FilterState
  setDraft: (patch: Partial<FilterState>) => void
  /** What is in force: the page shows what this lets through. */
  applied: FilterState
  parsed: ParsedFilters
  active: boolean
  /** Problems with the typed text, shown after a failed apply. */
  errors: FilterErrors
  /** Whether the draft differs from what is applied. */
  dirty: boolean
  /** Applies the draft; returns false, and shows the errors, if it is not valid. */
  apply: () => boolean
  /** Changes some filters at once, taking effect immediately (the quick filters, tags and badges use this). */
  set: (patch: Partial<FilterState>) => void
  reset: () => void
}

function sameState(a: FilterState, b: FilterState): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

/**
 * The filter state of the analyzer page. The text fields and checkboxes edit
 * a draft that "Apply" turns into the applied filters; the quick filters and
 * tags apply at once. The applied filters live in the page's query
 * parameters (through the router, so they follow the user from tab to tab and a
 * refresh or a shared link restores them).
 */
export function useFilters(): Filters {
  const [, setSearchParams] = useSearchParams()
  const [applied, setApplied] = useState<FilterState>(() => fromParams(new URLSearchParams(window.location.search)))
  const [draft, setDraftState] = useState<FilterState>(applied)
  const [errors, setErrors] = useState<FilterErrors>({})

  const commit = useCallback(
    (next: FilterState) => {
      setApplied(next)
      setDraftState(next)
      setErrors({})
      const params = toParams(next)
      // replace, not push: filtering is not navigation, so Back leaves the page
      // Built from the address bar, not from the router's last render: several
      // parts of the page change the query (these filters, a page's search box)
      // and a render may not have happened between two of their changes.
      const out = new URLSearchParams(window.location.search)
      for (const name of PARAM_NAMES) {
        if (params[name] === undefined) out.delete(name)
        else out.set(name, params[name])
      }
      setSearchParams(out, { replace: true })
    },
    [setSearchParams],
  )

  const setDraft = useCallback((patch: Partial<FilterState>) => {
    setDraftState((d) => ({ ...d, ...patch }))
    setErrors({})
  }, [])

  const apply = useCallback(() => {
    const next = tidy(draft)
    const found = validate(next)
    if (Object.keys(found).length > 0) {
      setErrors(found)
      return false
    }
    commit(next)
    return true
  }, [draft, commit])

  const set = useCallback(
    (patch: Partial<FilterState>) => {
      commit(tidy({ ...applied, ...patch }))
    },
    [applied, commit],
  )

  const reset = useCallback(() => commit(NO_FILTERS), [commit])

  const parsed = useMemo(() => parseFilters(applied), [applied])
  return {
    draft,
    setDraft,
    applied,
    parsed,
    active: isActive(applied),
    errors,
    dirty: !sameState(tidy(draft), applied),
    apply,
    set,
    reset,
  }
}
