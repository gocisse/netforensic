import { FLOW_STATUS_LABEL, plainFlow } from '../../plainLanguage'
import type { PlainFlow } from '../../plainLanguage'
import type { Flow } from '../../types'
import { Card, CardHeader } from '../ui/Card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/Table'

const STATUS_STYLE: Record<PlainFlow['status'], string> = {
  working: 'bg-success-50 dark:bg-success-500/15 text-success-700 dark:text-success-400',
  slow: 'bg-warning-50 dark:bg-warning-500/15 text-warning-700 dark:text-warning-400',
  broken: 'bg-error-50 dark:bg-error-500/15 text-error-700 dark:text-error-400',
}

interface Props {
  title: string
  flows: Flow[]
  emptyMessage: string
}

/** Connections in plain words: from, to, what and whether they work. */
export default function JuniorFlowTable({ title, flows, emptyMessage }: Props) {
  return (
    <Card data-testid="junior-flows">
      <CardHeader title={title} />
      {flows.length === 0 ? (
        <p className="border-t border-gray-100 dark:border-gray-800 px-6 py-4 text-theme-sm text-gray-600 dark:text-gray-400">{emptyMessage}</p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>From</TableHead>
                <TableHead>To</TableHead>
                <TableHead>What</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {flows.map((f) => {
                const p = plainFlow(f)
                return (
                  <TableRow key={f.id} data-testid="junior-flow-row" className="transition-colors hover:bg-gray-50/60 dark:hover:bg-white/[0.03]">
                    <TableCell className="whitespace-nowrap font-mono text-theme-xs text-gray-800 dark:text-white/90">{p.from}</TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-theme-xs text-gray-800 dark:text-white/90">{p.to}</TableCell>
                    <TableCell className="whitespace-nowrap">{p.what}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      <span data-testid="junior-flow-status" data-status={p.status} className={`rounded-full px-3 py-1 text-theme-xs font-semibold ${STATUS_STYLE[p.status]}`}>
                        {FLOW_STATUS_LABEL[p.status]}
                      </span>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </Card>
  )
}
