import { ipKey } from './ip'
import { parsePorts } from './ports'
import type { PortRange } from './ports'

/** What the user has asked to see. Empty fields and lists filter nothing. */
export interface FilterState {
  sourceIp: string
  destIp: string
  /** Ports and ranges as typed, such as "80,443,8000-9000". */
  port: string
  /** A protocol name, or 'All'. */
  protocol: string
  severities: string[]
  categories: string[]
}

export const NO_FILTERS: FilterState = { sourceIp: '', destIp: '', port: '', protocol: 'All', severities: [], categories: [] }

/** The filters in a form ready for matching. */
export interface ParsedFilters {
  sourceIp: string // as ipKey returns it, or ''
  destIp: string
  ports: PortRange[]
  protocol: string // '' for none
  severities: string[]
  categories: string[]
}

/** The severities, most severe first. */
export const SEVERITIES = ['CRITICAL', 'ERROR', 'WARNING', 'INFO'] as const

/** Problems with the text fields, to show next to them. */
export interface FilterErrors {
  sourceIp?: string
  destIp?: string
  port?: string
}

/** Checks the text fields. An empty result means the filters can be applied. */
export function validate(f: FilterState): FilterErrors {
  const errors: FilterErrors = {}
  if (f.sourceIp.trim() !== '' && ipKey(f.sourceIp.trim()) === null) errors.sourceIp = 'Not a valid IPv4 or IPv6 address.'
  if (f.destIp.trim() !== '' && ipKey(f.destIp.trim()) === null) errors.destIp = 'Not a valid IPv4 or IPv6 address.'
  const ports = parsePorts(f.port)
  if ('error' in ports) errors.port = ports.error
  return errors
}

/** Turns valid filters into the form used for matching. Invalid fields count as empty. */
export function parseFilters(f: FilterState): ParsedFilters {
  const ports = parsePorts(f.port)
  return {
    sourceIp: ipKey(f.sourceIp.trim()) ?? '',
    destIp: ipKey(f.destIp.trim()) ?? '',
    ports: 'ranges' in ports ? ports.ranges : [],
    protocol: f.protocol === 'All' ? '' : f.protocol,
    severities: f.severities,
    categories: f.categories,
  }
}

/** Whether any filter is set. */
export function isActive(f: FilterState): boolean {
  return (
    f.sourceIp.trim() !== '' ||
    f.destIp.trim() !== '' ||
    f.port.trim() !== '' ||
    f.protocol !== 'All' ||
    f.severities.length > 0 ||
    f.categories.length > 0
  )
}

/** Normalizes typed text: trims it, and tidies the port list. */
export function tidy(f: FilterState): FilterState {
  return {
    sourceIp: f.sourceIp.trim(),
    destIp: f.destIp.trim(),
    port: f.port
      .split(',')
      .map((p) => p.trim())
      .filter((p) => p !== '')
      .join(','),
    protocol: f.protocol || 'All',
    severities: f.severities,
    categories: f.categories,
  }
}

/** The query parameters of a filter, named as the server's /api/export-csv names them. Unset filters are left out. */
export function toParams(f: FilterState): Record<string, string> {
  const p: Record<string, string> = {}
  if (f.sourceIp) p.source_ip = f.sourceIp
  if (f.destIp) p.dest_ip = f.destIp
  if (f.port) p.port = f.port
  if (f.protocol !== 'All') p.protocol = f.protocol
  if (f.severities.length > 0) p.severity = f.severities.join(',')
  if (f.categories.length > 0) p.category = f.categories.join(',')
  return p
}

/** The names of the filter parameters. */
export const PARAM_NAMES = ['source_ip', 'dest_ip', 'port', 'protocol', 'severity', 'category'] as const

const list = (s: string | null): string[] =>
  (s ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter((x) => x !== '')

/**
 * Reads filters from URL parameters, dropping anything invalid: a bad link
 * should open the page, not break it.
 */
export function fromParams(params: URLSearchParams): FilterState {
  const f = tidy({
    sourceIp: params.get('source_ip') ?? '',
    destIp: params.get('dest_ip') ?? '',
    port: params.get('port') ?? '',
    protocol: params.get('protocol') ?? 'All',
    severities: list(params.get('severity'))
      .map((s) => s.toUpperCase())
      .filter((s) => (SEVERITIES as readonly string[]).includes(s)),
    categories: list(params.get('category')),
  })
  const errors = validate(f)
  return {
    ...f,
    sourceIp: errors.sourceIp ? '' : f.sourceIp,
    destIp: errors.destIp ? '' : f.destIp,
    port: errors.port ? '' : f.port,
    protocol: f.protocol.length > 32 || /[,;]/.test(f.protocol) ? 'All' : f.protocol,
  }
}
