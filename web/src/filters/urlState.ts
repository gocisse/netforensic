/** Reads the page's query parameters. */
export function readParams(): URLSearchParams {
  return new URLSearchParams(window.location.search)
}

/**
 * Sets query parameters in the address bar without adding a history entry, so
 * that a refresh or a copied link restores them. A value of undefined removes
 * the parameter; parameters not mentioned stay as they are.
 */
export function writeParams(updates: Record<string, string | undefined>): void {
  try {
    const params = readParams()
    for (const [k, v] of Object.entries(updates)) {
      if (v === undefined || v === '') params.delete(k)
      else params.set(k, v)
    }
    const query = params.toString()
    const url = window.location.pathname + (query ? `?${query}` : '') + window.location.hash
    window.history.replaceState(window.history.state, '', url)
  } catch {
    // an address bar that cannot be changed (a sandbox, say) only loses the persistence
  }
}
