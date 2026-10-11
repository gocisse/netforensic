/** One thing the command palette can do or jump to. */
export interface PaletteItem {
  id: string
  group: 'Pages' | 'Actions' | 'Issues'
  label: string
  /** A short note on the right, for example a shortcut key or the protocol of an issue. */
  hint?: string
  /** More text to search in, not shown. */
  keywords?: string
}

/** The groups in the order the palette lists them. */
export const GROUP_ORDER: PaletteItem['group'][] = ['Pages', 'Actions', 'Issues']

/**
 * The items that match what was typed: every word must occur in the label or
 * the keywords (any case). Items whose label starts with the first word come
 * first, then those with a word in the label, then the rest; within those
 * the groups keep their order. An empty query keeps everything. At most
 * `limit` items are returned.
 */
export function filterItems(items: PaletteItem[], query: string, limit = 50): PaletteItem[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  const groupRank = (g: PaletteItem['group']) => GROUP_ORDER.indexOf(g)
  const scored: { item: PaletteItem; rank: number; order: number }[] = []
  items.forEach((item, order) => {
    const label = item.label.toLowerCase()
    const hay = `${label} ${(item.keywords ?? '').toLowerCase()} ${(item.hint ?? '').toLowerCase()}`
    if (!words.every((w) => hay.includes(w))) return
    let rank = 2
    if (words.length === 0 || label.startsWith(words[0])) rank = 0
    else if (words.every((w) => label.includes(w))) rank = 1
    scored.push({ item, rank, order })
  })
  scored.sort((a, b) => a.rank - b.rank || groupRank(a.item.group) - groupRank(b.item.group) || a.order - b.order)
  return scored.slice(0, limit).map((s) => s.item)
}
