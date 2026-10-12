import { useContext } from 'react'
import type { LoadProgress } from '../types'
import { LoadProgressContext } from './context'

/** How far the lists of the analysis have arrived, or null when everything has. */
export function useLoadProgress(): LoadProgress | null {
  return useContext(LoadProgressContext)
}
