import { useState } from 'react'
import { severityColor, severityRank } from '../format'
import { formatVolume } from '../topology/model'
import type { Issue, TopologyNode } from '../types'
import type { Affected } from '../wireshark'
import IssueDetailsModal from './IssueDetailsModal'
import Modal from './Modal'
import Badge from './ui/Badge'

export interface Props {
  node: TopologyNode
  /** The issues that name the address. */
  issues: Issue[]
  captureName: string
  onClose: () => void
  /** Called with the addresses of an affected flow of an issue, to filter the page to it. */
  onFilterTo: (endpoints: Affected['endpoints']) => void
}

/**
 * The issues that involve one address of the diagram, worst first. A click on
 * an issue opens its details; closing those returns to this list.
 */
export default function NodeIssuesModal({ node, issues, captureName, onClose, onFilterTo }: Props) {
  const [open, setOpen] = useState<Issue | null>(null)
  const sorted = [...issues].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.count ?? 1) - (a.count ?? 1) || a.title.localeCompare(b.title))

  if (open) return <IssueDetailsModal issue={open} captureName={captureName} onClose={() => setOpen(null)} onFilterTo={onFilterTo} />

  return (
    <Modal title="Issues on this address" onClose={onClose} wide>
      <div className="mt-4 space-y-4" data-testid="node-issues">
        <div className="flex flex-wrap items-center gap-2" data-testid="node-issues-header">
          <h3 className="font-mono text-base font-semibold text-gray-800 dark:text-white/90" data-testid="node-issues-ip">
            {node.ip}
          </h3>
          <span className="rounded px-2 py-1 text-theme-xs font-medium bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300">{node.type.replace('_', ' ')}</span>
          <span className="text-theme-sm text-gray-600 dark:text-gray-400">
            {formatVolume(node.traffic_volume)} · {node.packets.toLocaleString()} packets
            {node.protocols.length > 0 && ` · ${node.protocols.join(', ')}`}
          </span>
        </div>
        {sorted.length === 0 ? (
          <p className="text-theme-sm text-gray-600 dark:text-gray-400" data-testid="node-issues-none">
            No issue involves this address.
          </p>
        ) : (
          <>
            <p className="text-theme-sm font-medium text-gray-600 dark:text-gray-400" data-testid="node-issues-count">
              {sorted.length.toLocaleString()} {sorted.length === 1 ? 'issue' : 'issues'}
            </p>
            <ul className="divide-y divide-gray-100 dark:divide-gray-800 rounded-xl border border-gray-200 dark:border-gray-800">
              {sorted.map((i) => (
                <li key={i.id}>
                  <button
                    type="button"
                    data-testid="node-issue"
                    onClick={() => setOpen(i)}
                    className="flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-gray-50 dark:hover:bg-white/[0.04]"
                  >
                    <Badge color={severityColor(i.severity)}>{i.severity}</Badge>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-theme-sm font-medium text-gray-800 dark:text-white/90">{i.title}</span>
                      <span className="line-clamp-2 text-theme-xs text-gray-600 dark:text-gray-400">{i.description}</span>
                    </span>
                    {(i.count ?? 1) > 1 && <span className="text-theme-xs tabular-nums text-gray-600 dark:text-gray-400">×{(i.count ?? 1).toLocaleString()}</span>}
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </Modal>
  )
}
