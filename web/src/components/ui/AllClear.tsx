/**
 * The state of a capture with no issues: a check mark in a shield, and a
 * friendly line. Used wherever a list of issues would otherwise be empty
 * because there is nothing wrong.
 */
export default function AllClear({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`flex flex-col items-center text-center ${compact ? 'px-4 py-6' : 'px-6 py-10'}`} data-testid="all-clear">
      <svg viewBox="0 0 96 96" className={compact ? 'h-16 w-16' : 'h-24 w-24'} role="img" aria-label="A shield with a check mark" fill="none">
        <circle cx="48" cy="48" r="44" className="fill-success-50 dark:fill-success-500/15" />
        <path d="M48 16 74 26v20c0 16-11 28-26 34C33 74 22 62 22 46V26l26-10z" className="fill-success-500" />
        <path d="m36 47 9 9 17-19" stroke="white" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="18" cy="22" r="3" className="fill-success-300" />
        <circle cx="80" cy="70" r="4" className="fill-success-300" />
        <circle cx="82" cy="24" r="2" className="fill-success-400" />
        <circle cx="14" cy="68" r="2" className="fill-success-400" />
      </svg>
      <p className="mt-4 text-lg font-semibold text-gray-800 dark:text-white/90">All clear! No network issues detected.</p>
      <p className="mt-1 text-theme-sm text-gray-600 dark:text-gray-400">Everything in this capture looks healthy.</p>
    </div>
  )
}
