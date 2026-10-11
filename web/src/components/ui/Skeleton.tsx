import type { HTMLAttributes } from 'react'
import { Card, CardHeader } from './Card'

/** A gray block that pulses while the content it stands for loads. */
export function Skeleton({ className = '', ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div aria-hidden="true" className={`animate-pulse rounded-lg bg-gray-200 dark:bg-gray-800 ${className}`} {...rest} />
}

/** Placeholder for the health card. */
export function HealthCardSkeleton() {
  return (
    <div className="flex flex-wrap items-center gap-6 rounded-2xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4 md:px-6" data-testid="skeleton-health">
      <div className="space-y-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-12 w-24" />
      </div>
      <div className="min-w-0 flex-1 basis-60 space-y-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-6 w-2/3" />
        <Skeleton className="h-4 w-1/2" />
      </div>
    </div>
  )
}

/** Placeholder for the protocol distribution. */
export function DistributionSkeleton() {
  return (
    <Card data-testid="skeleton-distribution">
      <CardHeader title="Protocol distribution" />
      <div className="space-y-4 border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
        <Skeleton className="h-4 w-full" />
        <div className="flex flex-wrap gap-2">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-8 w-24" />
          ))}
        </div>
      </div>
    </Card>
  )
}

/** Placeholder for a table: a header row and some body rows. */
export function TableSkeleton({ title, rows = 5, testId }: { title: string; rows?: number; testId: string }) {
  return (
    <Card data-testid={testId}>
      <CardHeader title={title} />
      <div className="space-y-3 border-t border-gray-100 dark:border-gray-800 p-4 sm:p-6">
        <Skeleton className="h-4 w-full" />
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    </Card>
  )
}

/** What the analysis page shows while the analysis loads: the shape of the page, not a spinner. */
export function AnalysisSkeleton() {
  return (
    <div className="space-y-6" data-testid="analysis-skeleton" role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading the analysis…</span>
      <Skeleton className="h-6 w-64" />
      <HealthCardSkeleton />
      <div className="grid gap-4 sm:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
      <DistributionSkeleton />
      <TableSkeleton title="Top issues" testId="skeleton-issues" />
      <TableSkeleton title="Busiest flows" rows={4} testId="skeleton-flows" />
    </div>
  )
}
