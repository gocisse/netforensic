import assert from 'node:assert/strict'
import { test } from 'node:test'
import { filterItems } from './search.ts'
import type { PaletteItem } from './search.ts'

const items: PaletteItem[] = [
  { id: 'page-tcp', group: 'Pages', label: 'TCP issues', hint: '1' },
  { id: 'page-dns', group: 'Pages', label: 'DNS issues', hint: '3' },
  { id: 'iss-1', group: 'Issues', label: 'Timeout Retransmit', hint: 'TCP', keywords: 'flow 10.0.0.1:40000 stalled' },
  { id: 'iss-2', group: 'Issues', label: 'DNS NXDOMAIN', hint: 'DNS', keywords: 'lookup failed' },
]
const ids = (q: string, limit?: number) => filterItems(items, q, limit).map((i) => i.id)

test('filterItems', async (t) => {
  const cases: { name: string; query: string; limit?: number; want: string[] }[] = [
    { name: 'case does not matter', query: 'TIMEOUT', want: ['iss-1'] },
    { name: 'every word must match', query: 'dns nxdomain', want: ['iss-2'] },
    { name: 'an address in the keywords finds the issue', query: '10.0.0.1', want: ['iss-1'] },
    { name: 'a label that starts with the word comes first', query: 'dns', want: ['page-dns', 'iss-2'] },
    { name: 'the hint is searched too', query: 'tcp', want: ['page-tcp', 'iss-1'] },
    { name: 'nothing matches', query: 'zzz', want: [] },
    { name: 'the limit is respected', query: '', limit: 2, want: ['page-tcp', 'page-dns'] },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.deepEqual(ids(c.query, c.limit), c.want))
  }
})
