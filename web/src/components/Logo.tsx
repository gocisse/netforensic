/** The product mark and name. */
export default function Logo({ size = 'md' }: { size?: 'md' | 'lg' }) {
  const box = size === 'lg' ? 'h-12 w-12 text-base' : 'h-9 w-9 text-sm'
  return (
    <div className="flex items-center gap-3">
      <div aria-hidden="true" className={`flex ${box} items-center justify-center rounded-lg bg-indigo-600 font-bold text-white`}>
        NF
      </div>
      <span className={`${size === 'lg' ? 'text-2xl' : 'text-lg'} font-semibold tracking-tight text-slate-900`}>Netforensic</span>
    </div>
  )
}
