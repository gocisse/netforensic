import { useEffect, useRef, useState } from 'react'
import { copyText } from '../../clipboard'
import type { Issue } from '../../types'
import { tsharkCommand, wiresharkCommand } from '../../wireshark'
import Button from '../ui/Button'

interface Props {
  issue: Issue
  /** The capture's file name, for the commands. */
  captureName: string
}

type Copied = 'filter' | 'wireshark' | 'tshark' | 'failed' | null

/**
 * What to do about an issue and how to check it in Wireshark: the
 * recommendation, the display filter that shows the packets in question in a
 * code block, and buttons that copy the filter or a command that opens the
 * capture with it. Wireshark registers no link that opens a capture with a
 * filter, so there is no "open" button, only commands to paste.
 */
export default function IssueGuidance({ issue, captureName }: Props) {
  const [copied, setCopied] = useState<Copied>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])

  const filter = issue.wireshark_filter
  const copy = async (what: Exclude<Copied, 'failed' | null>, text: string) => {
    const ok = await copyText(text)
    setCopied(ok ? what : 'failed')
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setCopied(null), 2500)
  }

  return (
    <div className="space-y-4" data-testid="issue-guidance">
      {issue.recommendation && (
        <div className="rounded-xl border border-blue-light-200 dark:border-blue-light-500/30 bg-blue-light-25 dark:bg-blue-light-500/10 p-4" data-testid="issue-recommendation">
          <p className="text-theme-xs font-semibold uppercase tracking-wide text-blue-light-700 dark:text-blue-light-400">What to do</p>
          <p className="mt-1 text-theme-sm text-gray-700 dark:text-gray-300">{issue.recommendation}</p>
        </div>
      )}
      {filter ? (
        <div data-testid="wireshark-filter-block">
          <p className="mb-1.5 text-theme-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Wireshark display filter</p>
          <pre className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-900 dark:bg-black/40 p-3 text-theme-sm text-gray-100">
            <code data-testid="wireshark-filter" className="whitespace-pre-wrap break-all font-mono">
              {filter}
            </code>
          </pre>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button size="sm" className="px-3 py-1.5 text-xs" data-testid="copy-filter" onClick={() => copy('filter', filter)}>
              {copied === 'filter' ? 'Copied!' : 'Copy Filter'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="px-3 py-1.5 text-xs"
              data-testid="copy-wireshark-command"
              title="Copies a command that opens the capture in Wireshark with this filter. Wireshark has no link that does it, so paste the command into a terminal in the capture's folder."
              onClick={() => copy('wireshark', wiresharkCommand(captureName, filter))}
            >
              {copied === 'wireshark' ? 'Copied!' : 'Copy Wireshark command'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="px-3 py-1.5 text-xs"
              data-testid="copy-tshark-command"
              title="Copies a tshark command that lists the matching packets"
              onClick={() => copy('tshark', tsharkCommand(captureName, filter))}
            >
              {copied === 'tshark' ? 'Copied!' : 'Copy tshark command'}
            </Button>
            <span role="status" aria-live="polite" data-testid="copy-status" className={`text-theme-xs ${copied === 'failed' ? 'text-error-600 dark:text-error-400' : 'text-gray-500 dark:text-gray-400'}`}>
              {copied === 'failed' ? 'Could not copy: select the filter and copy it by hand.' : copied ? 'Copied to the clipboard.' : ''}
            </span>
          </div>
          <p className="mt-2 text-theme-xs text-gray-500 dark:text-gray-400">
            Paste it into Wireshark&rsquo;s display filter bar (Ctrl+/) with <span className="font-mono">{captureName}</span> open. If the capture was filtered before it was uploaded, stream numbers may differ.
          </p>
        </div>
      ) : (
        <p className="text-theme-sm text-gray-500 dark:text-gray-400" data-testid="no-wireshark-filter">
          There is no Wireshark filter for this kind of issue.
        </p>
      )}
    </div>
  )
}
