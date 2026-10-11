import { useDashboardMode } from '../mode/useDashboardMode'

/**
 * The switch between the Junior and the Senior dashboard: "Mode: Junior /
 * Senior", with the active one in bold. Everything re-renders at once.
 */
export default function ModeToggle() {
  const { mode, toggleMode } = useDashboardMode()
  const junior = mode === 'junior'
  return (
    <button
      type="button"
      role="switch"
      aria-checked={junior}
      aria-label="Dashboard mode: Junior or Senior"
      title={junior ? 'Junior mode explains things in plain words. Switch to Senior for the technical detail.' : 'Senior mode shows the technical detail. Switch to Junior for plain-language explanations.'}
      data-testid="mode-toggle"
      data-mode={mode}
      onClick={toggleMode}
      className="flex h-10 items-center gap-2 rounded-lg border border-gray-200 dark:border-gray-800 px-3 text-theme-sm text-gray-700 dark:text-gray-300 transition-colors hover:bg-gray-100 dark:hover:bg-gray-800"
    >
      <span className="hidden sm:inline">Mode:</span>
      <span className={junior ? 'font-bold text-brand-600 dark:text-brand-400' : 'text-gray-600 dark:text-gray-400'}>Junior</span>
      <span aria-hidden="true" className={`relative h-5 w-9 flex-none rounded-full transition-colors ${junior ? 'bg-brand-500' : 'bg-gray-300 dark:bg-gray-600'}`}>
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${junior ? 'left-0.5' : 'left-[1.125rem]'}`} />
      </span>
      <span className={junior ? 'text-gray-600 dark:text-gray-400' : 'font-bold text-brand-600 dark:text-brand-400'}>Senior</span>
    </button>
  )
}
