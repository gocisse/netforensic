import { useCallback, useEffect, useMemo, useState } from 'react'
import { useLocation, useMatch, useNavigate } from 'react-router-dom'
import { useAnalysisCache } from '../analysis/useAnalysisCache'
import { isCaptureNote } from '../format'
import { useTheme } from '../hooks/useTheme'
import { PROTOCOL_PAGES, involvesProtocol } from '../protocols'
import { isTyping } from './isTyping'
import CommandPalette from './CommandPalette'
import type { PaletteItem } from './search'
import ShortcutsHelp from './ShortcutsHelp'

/**
 * The keyboard shortcuts of the dashboard, and the two dialogs they open:
 * Ctrl/Cmd+K the command palette, ? the help; 1-8 jump to the protocol pages
 * and 0 to the overview while an analysis is open. (Escape clears the filters:
 * the analysis page, which owns them, handles that.)
 */
export default function Shortcuts() {
  const [dialog, setDialog] = useState<'palette' | 'help' | null>(null)
  const navigate = useNavigate()
  const { search } = useLocation()
  const match = useMatch('/analysis/:id/*')
  const analysisId = match?.params.id
  const cache = useAnalysisCache()
  const { theme, toggleTheme } = useTheme()

  const result = cache.current && cache.current.id === analysisId ? cache.current.result : null

  const goTo = useCallback(
    (slug: string, extra?: Record<string, string>) => {
      if (!analysisId) return
      const params = new URLSearchParams(window.location.search)
      if (!extra?.q) params.delete('q')
      for (const [k, v] of Object.entries(extra ?? {})) params.set(k, v)
      const q = params.toString()
      navigate({ pathname: `/analysis/${analysisId}${slug ? `/${slug}` : ''}`, search: q ? `?${q}` : '' })
    },
    [analysisId, navigate],
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented) return
      const k = e.key.toLowerCase()
      if ((e.metaKey || e.ctrlKey) && !e.altKey && k === 'k') {
        e.preventDefault()
        setDialog((d) => (d === 'palette' ? null : 'palette'))
        return
      }
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target) || dialog || document.querySelector('[role="dialog"]')) return
      if (e.key === '?') {
        e.preventDefault()
        setDialog('help')
        return
      }
      if (analysisId && /^[0-8]$/.test(e.key)) {
        e.preventDefault()
        goTo(e.key === '0' ? '' : PROTOCOL_PAGES[Number(e.key) - 1].slug)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [analysisId, dialog, goTo])

  const close = useCallback(() => setDialog(null), [])

  const items = useMemo<PaletteItem[]>(() => {
    const out: PaletteItem[] = [{ id: 'page-upload', group: 'Pages', label: 'Analyze a capture', keywords: 'upload new file home' }]
    if (analysisId) {
      out.push({ id: 'page-overview', group: 'Pages', label: 'Overview', hint: '0', keywords: 'summary health' })
      PROTOCOL_PAGES.forEach((p, i) => out.push({ id: `page-${p.slug}`, group: 'Pages', label: p.title, hint: String(i + 1), keywords: p.protocol }))
    }
    out.push(
      { id: 'act-theme', group: 'Actions', label: theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme', keywords: 'dark light appearance' },
      { id: 'act-help', group: 'Actions', label: 'Show keyboard shortcuts', hint: '?', keywords: 'help keys' },
    )
    if (result) {
      for (const i of result.issues.filter((x) => !isCaptureNote(x))) {
        out.push({
          id: `issue-${i.id}`,
          group: 'Issues',
          label: i.title,
          hint: (i.protocols ?? []).join(' · ') || i.category,
          keywords: [i.description, i.flow_id, i.target, i.domain, i.category].filter(Boolean).join(' '),
        })
      }
    }
    return out
  }, [analysisId, theme, result])

  const choose = (item: PaletteItem) => {
    setDialog(null)
    if (item.id === 'page-upload') navigate({ pathname: '/', search })
    else if (item.id === 'page-overview') goTo('')
    else if (item.id.startsWith('page-')) goTo(item.id.slice(5))
    else if (item.id === 'act-theme') toggleTheme()
    else if (item.id === 'act-help') setDialog('help')
    else if (item.id.startsWith('issue-') && result) {
      const issue = result.issues.find((x) => `issue-${x.id}` === item.id)
      const page = PROTOCOL_PAGES.find((p) => issue && involvesProtocol(issue, p.protocol))
      if (issue && page) goTo(page.slug, { q: issue.title })
      else goTo('')
    }
  }

  return (
    <>
      {dialog === 'palette' && <CommandPalette items={items} onChoose={choose} onClose={close} />}
      {dialog === 'help' && <ShortcutsHelp onClose={close} />}
    </>
  )
}
