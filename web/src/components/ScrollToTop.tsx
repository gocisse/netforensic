import { useEffect, useState } from 'react'
import { ArrowUpIcon } from '../icons'

/** How far down the page (px) the button appears. */
const SHOW_AFTER = 800

/** A small button at the corner that appears once the page is scrolled down and takes the reader back to the top. */
export default function ScrollToTop() {
  const [shown, setShown] = useState(false)
  useEffect(() => {
    const onScroll = () => setShown(window.scrollY > SHOW_AFTER)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])
  if (!shown) return null
  return (
    <button
      type="button"
      data-testid="scroll-to-top"
      aria-label="Scroll to top"
      title="Scroll to top"
      onClick={() => window.scrollTo({ top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })}
      className="fixed bottom-6 left-6 z-40 flex h-10 w-10 animate-fade-in items-center justify-center rounded-full border border-gray-200 dark:border-gray-800 bg-white/90 dark:bg-gray-900/90 text-gray-600 dark:text-gray-400 shadow-theme-md backdrop-blur-[2px] hover:bg-gray-50 dark:hover:bg-gray-800 hover:text-gray-800 dark:hover:text-white/90 md:left-auto md:right-6"
    >
      <ArrowUpIcon className="h-5 w-5" />
    </button>
  )
}
