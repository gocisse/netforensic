import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAnalysisView } from '../analysis/view'
import { useAuth } from '../auth/useAuth'
import NetworkTopology from '../components/NetworkTopology'
import NodeIssuesModal from '../components/NodeIssuesModal'
import Alert from '../components/ui/Alert'
import Button from '../components/ui/Button'
import { Card, CardHeader } from '../components/ui/Card'
import { TableSkeleton } from '../components/ui/Skeleton'
import { displayIP } from '../filters/ip'
import { tidy, toParams } from '../filters/model'
import { TONE_COLORS, edgeProtocols, edgeSeverities, issuesForIp, nodeMatches } from '../topology/model'
import type { TopologyFilter } from '../topology/model'
import type { Severity, Topology as TopologyData } from '../types'
import type { Affected } from '../wireshark'

const dot = (tone: 'problem' | 'busy' | 'ok') => <span aria-hidden="true" className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: TONE_COLORS[tone].light }} />

function Check({ label, count, checked, onChange, testId }: { label: string; count?: number; checked: boolean; onChange: (on: boolean) => void; testId: string }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-theme-sm text-gray-700 dark:text-gray-300">
      <input type="checkbox" data-testid={testId} checked={checked} onChange={(e) => onChange(e.target.checked)} className="h-4 w-4 rounded border-gray-300 dark:border-gray-700 accent-brand-500" />
      {label}
      {count !== undefined && <span className="text-theme-xs text-gray-500 dark:text-gray-400">({count.toLocaleString()})</span>}
    </label>
  )
}

/**
 * The Network Topology page: the addresses of the capture and the traffic
 * between them as an interactive diagram. Addresses with issues are red, the
 * busiest are yellow. Filter by protocol and by the severity of the issues on a
 * connection, search for an address, click one to see its issues.
 */
export default function Topology() {
  const { id, reportable, issuesLoaded, captureName, filters } = useAnalysisView()
  const { api } = useAuth()
  const navigate = useNavigate()
  const [attempt, setAttempt] = useState(0)
  // What was fetched, and for which request: an answer to an older request is not the current one.
  const [fetched, setFetched] = useState<{ key: string; topo?: TopologyData; error?: string } | null>(null)
  const key = `${id}:${attempt}`
  const topo = fetched?.key === key ? (fetched.topo ?? null) : null
  const error = fetched?.key === key ? (fetched.error ?? null) : null
  const [protocolsOff, setProtocolsOff] = useState<ReadonlySet<string>>(new Set())
  const [severitiesOff, setSeveritiesOff] = useState<ReadonlySet<Severity>>(new Set())
  const [search, setSearch] = useState('')
  const [resetToken, setResetToken] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    const ctl = new AbortController()
    api
      .getTopology(id, ctl.signal)
      .then((t) => setFetched({ key, topo: t }))
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === 'AbortError') return
        setFetched({ key, error: e instanceof Error ? e.message : 'The topology could not be loaded.' })
      })
    return () => ctl.abort()
  }, [api, id, key])

  const protocols = useMemo(() => (topo ? edgeProtocols(topo) : []), [topo])
  const severities = useMemo(() => (topo ? edgeSeverities(topo) : []), [topo])
  const filter = useMemo<TopologyFilter>(
    () => ({ protocols: new Set(protocols.map((p) => p.protocol).filter((p) => !protocolsOff.has(p))), severities: new Set(severities.filter((s) => !severitiesOff.has(s))) }),
    [protocols, severities, protocolsOff, severitiesOff],
  )
  const toggle = <T,>(set: ReadonlySet<T>, v: T, on: boolean): Set<T> => {
    const next = new Set(set)
    if (on) next.delete(v)
    else next.add(v)
    return next
  }

  const node = topo?.nodes.find((n) => n.ip === selected) ?? null
  const nodeIssues = useMemo(() => (selected ? issuesForIp(reportable, selected) : []), [reportable, selected])
  const matchCount = useMemo(() => (topo && search.trim() !== '' ? topo.nodes.filter((n) => nodeMatches(n, search)).length : 0), [topo, search])

  // An affected flow in an issue's details filters the Bad Traffic page to it.
  const filterTo = useCallback(
    (eps: Affected['endpoints']) => {
      if (eps.length === 0) return
      const next = toParams(tidy({ ...filters.applied, sourceIp: displayIP(eps[0].ip), destIp: eps.length > 1 ? displayIP(eps[1].ip) : '' }))
      const out = new URLSearchParams(window.location.search)
      for (const [k, v] of Object.entries(next)) if (v !== undefined) out.set(k, v)
      setSelected(null)
      navigate({ pathname: `/analysis/${id}/bad`, search: out.toString() })
    },
    [filters.applied, id, navigate],
  )

  const onSearchKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'Enter' || !topo) return
    const first = topo.nodes.find((n) => nodeMatches(n, search))
    if (first) setSelected(first.ip)
  }

  if (error) {
    return (
      <div className="space-y-4" data-testid="topology-error">
        <Alert variant="error" title="The network diagram could not be loaded" role="alert">
          {error}
        </Alert>
        <Button variant="outline" size="sm" onClick={() => setAttempt((a) => a + 1)} data-testid="topology-retry">
          Try again
        </Button>
      </div>
    )
  }
  if (!topo) return <TableSkeleton title="Network topology" rows={6} testId="skeleton-topology" />
  if (topo.nodes.length === 0) {
    return (
      <Card>
        <p className="px-6 py-8 text-center text-theme-sm text-gray-600 dark:text-gray-400" data-testid="topology-empty">
          This capture has no flows between IP addresses to draw.
        </p>
      </Card>
    )
  }

  const problems = topo.nodes.filter((n) => n.is_problematic).length
  return (
    <div className="space-y-4" data-testid="topology">
      <Card>
        <CardHeader
          title="Network topology"
          description={
            <span data-testid="topology-summary">
              {topo.nodes.length.toLocaleString()} {topo.nodes.length === 1 ? 'address' : 'addresses'}, {topo.edges.length.toLocaleString()} {topo.edges.length === 1 ? 'connection' : 'connections'}, {problems.toLocaleString()} with issues
              {topo.truncated && ` (the most telling of ${topo.total_nodes.toLocaleString()} addresses and ${topo.total_edges.toLocaleString()} connections)`}
              {!issuesLoaded && ' (issues are still loading)'}
            </span>
          }
          action={
            <Button variant="outline" size="sm" onClick={() => setResetToken((t) => t + 1)} data-testid="topology-reset">
              Reset View
            </Button>
          }
        />
        <div className="space-y-4 border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
          <div className="flex flex-wrap items-end gap-4">
            <div className="min-w-0 flex-1">
              <label htmlFor="topology-search" className="mb-2 block text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
                Find an address
              </label>
              <input
                id="topology-search"
                data-testid="topology-search"
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={onSearchKey}
                placeholder="An address; Enter opens its issues"
                autoComplete="off"
                spellCheck={false}
                className="h-10 w-full max-w-md rounded-lg border border-gray-300 dark:border-gray-700 bg-transparent dark:bg-gray-900 px-3 text-sm text-gray-800 dark:text-white/90 placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
              />
              {search.trim() !== '' && (
                <p className="mt-2 text-theme-xs text-gray-600 dark:text-gray-400" data-testid="topology-matches">
                  {matchCount === 0 ? 'No address matches.' : `${matchCount.toLocaleString()} highlighted.`}
                </p>
              )}
            </div>
            <ul className="flex flex-wrap items-center gap-4 text-theme-xs text-gray-600 dark:text-gray-400" data-testid="topology-legend" aria-label="Legend">
              <li className="inline-flex items-center gap-2">{dot('problem')} Has issues</li>
              <li className="inline-flex items-center gap-2">{dot('busy')} High traffic</li>
              <li className="inline-flex items-center gap-2">{dot('ok')} Healthy</li>
              <li>Size: traffic</li>
              <li>Red line: issues</li>
            </ul>
          </div>
          <div className="flex flex-wrap gap-x-8 gap-y-3">
            <fieldset data-testid="topology-protocols">
              <legend className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Protocols</legend>
              <div className="flex flex-wrap gap-4">
                {protocols.map((p) => (
                  <Check key={p.protocol} testId={`topology-protocol-${p.protocol}`} label={p.protocol} count={p.edges} checked={!protocolsOff.has(p.protocol)} onChange={(on) => setProtocolsOff(toggle(protocolsOff, p.protocol, on))} />
                ))}
              </div>
            </fieldset>
            {severities.length > 0 && (
              <fieldset data-testid="topology-severities">
                <legend className="mb-2 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Worst severity on a connection</legend>
                <div className="flex flex-wrap gap-4">
                  {severities.map((s) => (
                    <Check key={s} testId={`topology-severity-${s}`} label={s} checked={!severitiesOff.has(s)} onChange={(on) => setSeveritiesOff(toggle(severitiesOff, s, on))} />
                  ))}
                </div>
              </fieldset>
            )}
          </div>
          <NetworkTopology topology={topo} filter={filter} search={search} resetToken={resetToken} onSelect={setSelected} />
          <p className="text-theme-xs text-gray-500 dark:text-gray-400">Scroll to zoom, drag to pan, click an address to see its issues.</p>
        </div>
      </Card>
      {node && <NodeIssuesModal node={node} issues={nodeIssues} captureName={captureName} onClose={() => setSelected(null)} onFilterTo={filterTo} />}
    </div>
  )
}
