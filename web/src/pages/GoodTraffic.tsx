import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { useDeferredValue, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAnalysisView } from '../analysis/view'
import { copyText } from '../clipboard'
import { FlowEndpoints } from '../components/FlowTable'
import AllClear from '../components/ui/AllClear'
import { TableSkeleton } from '../components/ui/Skeleton'
import Button from '../components/ui/Button'
import { Card, CardHeader } from '../components/ui/Card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/Table'
import { useScrollMargin } from '../hooks/useScrollMargin'
import { formatBytes, formatMs, protocolColor } from '../format'
import { matchesGoodSearch, sortGoodFlows } from '../goodTraffic'
import type { GoodSortKey, SortDir } from '../goodTraffic'
import { useToast } from '../toast/useToast'
import { tsharkCommand } from '../wireshark'

/** The height of a row in px before it is drawn and measured. */
const ROW_HEIGHT = 57

const COLUMNS: { key: GoodSortKey; label: string; right?: boolean }[] = [
  { key: 'flow', label: 'Flow' },
  { key: 'packets', label: 'Packets', right: true },
  { key: 'bytes', label: 'Bytes', right: true },
  { key: 'rtt', label: 'Avg RTT', right: true },
  { key: 'protocol', label: 'Protocol' },
  { key: 'status', label: 'Status' },
]

/**
 * The Good Traffic tab: the flows no issue names, in a sortable, searchable
 * table (busiest first), and a master Wireshark filter that hides everything
 * the issues point at.
 */
export default function GoodTraffic() {
  const { result, id, captureName, flowsLoaded } = useAnalysisView()
  const toast = useToast()
  const healthy = useMemo(() => result.healthy_flows ?? [], [result])
  const [query, setQuery] = useState('')
  const deferred = useDeferredValue(query)
  const [sort, setSort] = useState<{ key: GoodSortKey; dir: SortDir }>({ key: 'packets', dir: 'desc' })
  const master = result.good_traffic_filter ?? ''

  const rows = useMemo(() => sortGoodFlows(healthy.filter((f) => matchesGoodSearch(f, deferred)), sort.key, sort.dir), [healthy, deferred, sort])

  // The table is virtual: only the rows in view are drawn, between two spacer rows that keep the scroll height.
  const bodyTop = useRef<HTMLTableRowElement>(null)
  const scrollMargin = useScrollMargin(bodyTop)
  // The React Compiler is not used here, so the library's un-memoizable functions are fine.
  // oxlint-disable-next-line react/incompatible-library
  const virtualizer = useWindowVirtualizer({ count: rows.length, estimateSize: () => ROW_HEIGHT, getItemKey: (i) => rows[i].id, overscan: 8, scrollMargin })
  const drawn = virtualizer.getVirtualItems()
  const padTop = drawn.length > 0 ? drawn[0].start - scrollMargin : 0
  const padBottom = drawn.length > 0 ? virtualizer.getTotalSize() - (drawn[drawn.length - 1].end - scrollMargin) : 0

  const toggleSort = (key: GoodSortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: key === 'flow' || key === 'protocol' ? 'asc' : 'desc' }))
  }
  const copy = async (text: string, done: string) => {
    if (await copyText(text)) toast.show(done)
    else toast.show('Could not copy. Select the text and copy it by hand.', 'error')
  }

  if (!flowsLoaded) {
    return (
      <div data-testid="good-loading">
        <TableSkeleton title="Healthy flows" rows={6} testId="skeleton-good-flows" />
      </div>
    )
  }
  if (healthy.length === 0) {
    return (
      <Card>
        <div className="px-6 py-8 text-center" data-testid="good-empty">
          <p className="text-base font-medium text-gray-800 dark:text-white/90">All flows have issues. See Bad Traffic tab.</p>
          <p className="mt-1 text-theme-sm text-gray-500 dark:text-gray-400">{result.total_flows === 0 ? 'This capture holds no flows.' : 'Every flow in this capture is named by at least one issue.'}</p>
          {result.total_flows > 0 && (
            <Link to={`/analysis/${id}/bad`} className="mt-3 inline-block text-theme-sm font-medium text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300">
              Go to Bad Traffic
            </Link>
          )}
        </div>
      </Card>
    )
  }

  return (
    <div className="space-y-6" data-testid="good-traffic">
      <Card>
        <CardHeader
          title="Healthy flows"
          description={
            <span data-testid="good-summary">
              Showing {rows.length.toLocaleString()} of {healthy.length.toLocaleString()} healthy {healthy.length === 1 ? 'flow' : 'flows'}
            </span>
          }
        />
        <div className="border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
          <label htmlFor="good-search" className="mb-2 block text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            Search healthy flows
          </label>
          <input
            id="good-search"
            data-testid="good-search"
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
            }}
            placeholder="An address, a port or a protocol"
            autoComplete="off"
            spellCheck={false}
            className="h-10 w-full max-w-lg rounded-lg border border-gray-300 dark:border-gray-700 bg-transparent dark:bg-gray-900 px-3 text-sm text-gray-800 dark:text-white/90 placeholder:text-gray-500 dark:placeholder:text-gray-400 focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
          />
        </div>
        {rows.length === 0 ? (
          <div className="border-t border-gray-100 dark:border-gray-800 px-6 py-8 text-center" data-testid="good-no-match">
            <p className="text-base font-medium text-gray-800 dark:text-white/90">No healthy flows match your search</p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setQuery('')}>
              Clear search
            </Button>
          </div>
        ) : (
          <div className="relative overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  {COLUMNS.map((c) => (
                    <TableHead key={c.key} className={c.right ? 'text-right' : ''} aria-sort={sort.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                      <button type="button" onClick={() => toggleSort(c.key)} data-testid={`good-sort-${c.key}`} className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-gray-800 dark:hover:text-white/90">
                        {c.label}
                        <span aria-hidden="true">{sort.key === c.key ? (sort.dir === 'asc' ? '▲' : '▼') : ''}</span>
                      </button>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                <tr ref={bodyTop} aria-hidden="true" style={{ height: padTop }}>
                  <td colSpan={COLUMNS.length} className="p-0" />
                </tr>
                {drawn.map((v) => {
                  const f = rows[v.index]
                  return (
                    <TableRow key={f.id} data-testid="good-flow-row" data-index={v.index} ref={virtualizer.measureElement}>
                      <TableCell className="max-w-xs text-gray-800 dark:text-white/90">
                        <FlowEndpoints flow={f} />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{f.packet_count.toLocaleString()}</TableCell>
                      <TableCell className="whitespace-nowrap text-right tabular-nums">{formatBytes(f.bytes_sent + f.bytes_recv)}</TableCell>
                      <TableCell className="whitespace-nowrap text-right tabular-nums">{formatMs(f.avg_rtt_ms)}</TableCell>
                      <TableCell className="whitespace-nowrap">
                        <span className={`rounded px-2 py-1 text-theme-xs font-medium ${protocolColor(f.protocol).badge}`}>{f.protocol || 'Other'}</span>
                        {f.app_protocol && <span className={`ml-1 rounded px-2 py-1 text-theme-xs font-medium ${protocolColor(f.app_protocol).badge}`}>{f.app_protocol}</span>}
                      </TableCell>
                      <TableCell className="whitespace-nowrap" data-testid="good-status" data-status={f.status === 'slow' ? 'slow' : 'ok'}>
                        {f.status === 'slow' ? (
                          <span className="font-medium text-warning-700 dark:text-warning-400" title="No issue names this flow, but its timings are slow">
                            Slow
                          </span>
                        ) : (
                          <span className="font-semibold text-success-700 dark:text-success-400" title="No issue names this flow">
                            <span aria-hidden="true">✓</span>
                            <span className="sr-only">Healthy</span>
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
                <tr aria-hidden="true" style={{ height: padBottom }}>
                  <td colSpan={COLUMNS.length} className="p-0" />
                </tr>
              </TableBody>
            </Table>
          </div>
        )}
      </Card>

      <Card data-testid="master-filter-card">
        <CardHeader title="Master Wireshark filter" description="Hides every packet any issue points at, so that what is left is the traffic no issue is about." />
        <div className="space-y-3 border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
          {master ? (
            <>
              <pre className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-900 dark:bg-black/40 p-3 text-theme-sm text-gray-100">
                <code data-testid="master-filter" className="whitespace-pre-wrap break-all font-mono">
                  {master}
                </code>
              </pre>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" className="px-3 py-2 text-xs" data-testid="copy-master-filter" onClick={() => copy(master, 'Filter copied to clipboard')}>
                  Copy Filter
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="px-3 py-2 text-xs"
                  data-testid="show-good-packets"
                  title="Copies a tshark command that lists every packet the filter keeps"
                  onClick={() => copy(tsharkCommand(captureName, master), 'tshark command copied to clipboard')}
                >
                  Show all good packets
                </Button>
              </div>
            </>
          ) : (
            <div data-testid="master-filter-none">
              <AllClear compact testId="master-filter-clear" title="Nothing to exclude." detail="No issue has a Wireshark filter, so every packet of the capture is good traffic." />
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}
