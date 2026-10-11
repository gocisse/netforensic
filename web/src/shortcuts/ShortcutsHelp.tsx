import Modal from '../components/Modal'

const MOD = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl'

const ROWS: { keys: string[]; what: string }[] = [
  { keys: [MOD, 'K'], what: 'Open the command palette: search issues, jump to a page' },
  { keys: ['1', '–', '8'], what: 'Jump to TCP, UDP, DNS, HTTP, TLS, SIP, DHCPv6 or QUIC (on an analysis)' },
  { keys: ['0'], what: 'Back to the overview (on an analysis)' },
  { keys: ['Esc'], what: 'Close a dialog; otherwise clear the filters' },
  { keys: ['?'], what: 'Show this help' },
]

/** The dialog that lists the keyboard shortcuts. */
export default function ShortcutsHelp({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Keyboard shortcuts" onClose={onClose}>
      <dl className="mt-4 space-y-3" data-testid="shortcuts-help">
        {ROWS.map((r) => (
          <div key={r.what} className="flex items-start justify-between gap-4">
            <dd className="min-w-0 text-theme-sm text-gray-700 dark:text-gray-300">{r.what}</dd>
            <dt className="flex flex-none gap-1">
              {r.keys.map((k, i) =>
                k === '–' ? (
                  <span key={i} aria-hidden="true" className="px-1 text-gray-600 dark:text-gray-400">
                    –
                  </span>
                ) : (
                  <kbd key={i} className="min-w-6 rounded border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 px-2 py-1 text-center font-mono text-theme-xs text-gray-800 dark:text-gray-200">
                    {k}
                  </kbd>
                ),
              )}
            </dt>
          </div>
        ))}
      </dl>
    </Modal>
  )
}
