import type { FormEvent } from 'react'
import { SEVERITIES } from '../filters/model'
import type { Filters } from '../filters/useFilters'
import { DownloadIcon, FilterIcon } from '../icons'
import Button from './ui/Button'
import { Card, CardBody, CardHeader } from './ui/Card'
import Field from './ui/Field'
import QuickFilters from './QuickFilters'

export interface CategoryOption {
  name: string
  count: number
}

interface Props {
  filters: Filters
  /** Every protocol detected in the capture, transport and application. */
  protocols: string[]
  /** The categories of the capture's issues, with how many issues each has. */
  categories: CategoryOption[]
  /** The severities that occur in the capture's issues. */
  severities: string[]
  onExport: () => void
  exporting: boolean
  /** Why the export is unavailable, if it is. */
  exportDisabledReason?: string
  exportError?: string | null
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'text-error-700 dark:text-error-400',
  ERROR: 'text-error-600 dark:text-error-400',
  WARNING: 'text-warning-600 dark:text-warning-400',
  INFO: 'text-blue-light-600 dark:text-blue-light-400',
}

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((x) => x !== value) : [...list, value]
}

function Checkbox({ label, checked, onChange, className = '', testId, hint }: { label: string; checked: boolean; onChange: () => void; className?: string; testId?: string; hint?: string }) {
  return (
    <label
      className={`inline-flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-1.5 text-theme-sm transition-colors ${
        checked ? 'border-brand-500 bg-brand-25 dark:bg-brand-500/10' : 'border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/60'
      }`}
    >
      <input type="checkbox" checked={checked} onChange={onChange} data-testid={testId} className="h-4 w-4 rounded border-gray-300 dark:border-gray-700 accent-brand-500" />
      <span className={`font-medium ${className}`}>{label}</span>
      {hint && <span className="text-theme-xs text-gray-400">{hint}</span>}
    </label>
  )
}

/**
 * The filters: IP addresses, ports, protocol, severity and category, applied
 * together with the "Apply Filters" button (or Enter), and the quick filters
 * that apply at once.
 */
export default function FilterPanel({ filters, protocols, categories, severities, onExport, exporting, exportDisabledReason, exportError }: Props) {
  const { draft, setDraft, errors } = filters
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    filters.apply()
  }
  const severityOptions = SEVERITIES.filter((s) => s !== 'CRITICAL' || severities.includes('CRITICAL'))

  return (
    <Card data-testid="filter-panel">
      <CardHeader
        title="Filters"
        description="Narrow the issues, flows and protocol distribution below. The health score and root cause always describe the whole capture."
        action={<FilterIcon className="h-5 w-5 text-gray-400" />}
      />
      <CardBody className="space-y-5">
        <QuickFilters filters={filters} />

        <form onSubmit={onSubmit} className="space-y-5" noValidate>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div data-testid="filter-source-ip">
              <Field
                id="filter-source-ip"
                label="Source IP"
                placeholder="10.0.0.1 or 2001:db8::1"
                value={draft.sourceIp}
                onChange={(e) => setDraft({ sourceIp: e.target.value })}
                error={Boolean(errors.sourceIp)}
                hint={errors.sourceIp ?? 'Matches either end of a flow.'}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(errors.sourceIp)}
              />
            </div>
            <div data-testid="filter-dest-ip">
              <Field
                id="filter-dest-ip"
                label="Destination IP"
                placeholder="10.0.0.2 or 2001:db8::2"
                value={draft.destIp}
                onChange={(e) => setDraft({ destIp: e.target.value })}
                error={Boolean(errors.destIp)}
                hint={errors.destIp ?? 'With a source IP, the two ends of one flow.'}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(errors.destIp)}
              />
            </div>
            <div data-testid="filter-port">
              <Field
                id="filter-port"
                label="Port"
                placeholder="80,443,8000-9000"
                value={draft.port}
                onChange={(e) => setDraft({ port: e.target.value })}
                error={Boolean(errors.port)}
                hint={errors.port ?? 'Ports and ranges, separated by commas.'}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(errors.port)}
              />
            </div>
            <div>
              <label htmlFor="filter-protocol" className="mb-1.5 block text-sm font-medium text-gray-700 dark:text-gray-300">
                Protocol
              </label>
              <select
                id="filter-protocol"
                data-testid="protocol-filter"
                value={draft.protocol}
                onChange={(e) => setDraft({ protocol: e.target.value })}
                className="h-11 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-transparent dark:bg-gray-900 px-3 text-sm text-gray-800 dark:text-white/90 shadow-theme-xs focus:border-brand-300 dark:focus:border-brand-500/60 focus:outline-hidden focus:ring-3 focus:ring-brand-500/10"
              >
                <option value="All">All protocols</option>
                {protocols.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
              <p className="mt-1.5 text-theme-xs text-gray-500 dark:text-gray-400">Transport or application protocol.</p>
            </div>
          </div>

          <div className="grid gap-5 lg:grid-cols-2">
            <fieldset data-testid="filter-severity">
              <legend className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">Severity</legend>
              <div className="flex flex-wrap gap-2">
                {severityOptions.map((s) => (
                  <Checkbox key={s} label={s} className={SEVERITY_STYLE[s]} checked={draft.severities.includes(s)} onChange={() => setDraft({ severities: toggle(draft.severities, s) })} testId={`severity-${s}`} />
                ))}
              </div>
            </fieldset>
            <fieldset data-testid="filter-category">
              <legend className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">Category</legend>
              <div className="flex flex-wrap gap-2">
                {categories.length === 0 && <span className="text-theme-sm text-gray-500 dark:text-gray-400">This capture has no issues to categorize.</span>}
                {categories.map((c) => (
                  <Checkbox
                    key={c.name}
                    label={c.name}
                    hint={String(c.count)}
                    checked={draft.categories.includes(c.name)}
                    onChange={() => setDraft({ categories: toggle(draft.categories, c.name) })}
                    testId={`category-${c.name}`}
                  />
                ))}
              </div>
            </fieldset>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" data-testid="apply-filters" size="sm">
              Apply Filters
            </Button>
            <Button type="button" variant="outline" size="sm" data-testid="reset-filters" onClick={filters.reset}>
              Reset
            </Button>
            {filters.dirty && !Object.keys(errors).length && <span className="text-theme-xs text-gray-500 dark:text-gray-400">Changes not applied yet.</span>}
            <div className="ml-auto flex flex-col items-end gap-1">
              <Button
                type="button"
                variant="outline"
                size="sm"
                data-testid="export-filtered"
                loading={exporting}
                disabled={Boolean(exportDisabledReason)}
                title={exportDisabledReason ?? (filters.active ? 'Download the filtered flows, issues and protocols as CSV files (a zip)' : 'No filters are set: download everything as CSV files (a zip)')}
                startIcon={<DownloadIcon className="h-4 w-4" />}
                onClick={onExport}
              >
                {exporting ? 'Exporting…' : filters.active ? 'Export Filtered' : 'Export CSV'}
              </Button>
              {exportError && (
                <p role="alert" data-testid="export-error" className="text-theme-xs text-error-600 dark:text-error-400">
                  {exportError}
                </p>
              )}
            </div>
          </div>
        </form>
      </CardBody>
    </Card>
  )
}
