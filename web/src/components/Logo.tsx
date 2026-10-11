/** The product mark and name. */
export default function Logo({ size = 'md', showName = true }: { size?: 'md' | 'lg'; showName?: boolean }) {
  const box = size === 'lg' ? 'h-12 w-12 text-base' : 'h-9 w-9 text-sm'
  return (
    <div className="flex items-center gap-3">
      <div aria-hidden="true" className={`flex ${box} flex-none items-center justify-center rounded-xl bg-brand-500 font-bold text-white shadow-theme-xs`}>
        NF
      </div>
      {showName && <span className={`${size === 'lg' ? 'text-theme-xl' : 'text-lg'} font-semibold tracking-tight text-gray-800 dark:text-white/90`}>Netforensic</span>}
    </div>
  )
}
