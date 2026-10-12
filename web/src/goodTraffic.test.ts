import assert from 'node:assert/strict'
import { test } from 'node:test'
import { matchesGoodSearch, sortGoodFlows } from './goodTraffic.ts'
import type { Flow } from './types.ts'

const flow = (over: Partial<Flow>): Flow => ({
  id: 'f', src_ip: '10.0.0.1', dst_ip: '10.0.0.2', src_port: 1000, dst_port: 80, protocol: 'TCP', start_time: '', end_time: '',
  packet_count: 1, bytes_sent: 0, bytes_recv: 0, retransmits: 0, setup_time_ms: 0, ttfb_ms: 0, avg_rtt_ms: 0, max_rtt_ms: 0, ...over,
})

test('matchesGoodSearch', async (t) => {
  const f = flow({ dst_ip: '192.168.1.9', dst_port: 443, app_protocol: 'TLS' })
  const cases: { name: string; query: string; want: boolean }[] = [
    { name: 'empty matches', query: '  ', want: true },
    { name: 'an address', query: '192.168.1.9', want: true },
    { name: 'part of an address', query: '168.1', want: true },
    { name: 'an address and port', query: '192.168.1.9:443', want: true },
    { name: 'a port', query: '443', want: true },
    { name: 'a transport protocol, in any case', query: 'tcp', want: true },
    { name: 'an application protocol', query: 'tls', want: true },
    { name: 'every word must match', query: 'tls 8080', want: false },
    { name: 'no match', query: '10.9.9.9', want: false },
  ]
  for (const c of cases) await t.test(c.name, () => assert.equal(matchesGoodSearch(f, c.query), c.want))
})

test('sortGoodFlows', async (t) => {
  const flows = [
    flow({ id: 'a', packet_count: 5, bytes_sent: 10, avg_rtt_ms: 3, protocol: 'UDP' }),
    flow({ id: 'b', packet_count: 9, bytes_sent: 1, avg_rtt_ms: 0, protocol: 'TCP' }),
    flow({ id: 'c', packet_count: 9, bytes_sent: 50, avg_rtt_ms: 8, protocol: 'TCP', status: 'slow' }),
  ]
  const ids = (k: Parameters<typeof sortGoodFlows>[1], d: 'asc' | 'desc') => sortGoodFlows(flows, k, d).map((f) => f.id).join('')
  const cases: [string, Parameters<typeof sortGoodFlows>[1], 'asc' | 'desc', string][] = [
    ['packets descending, ties by ID', 'packets', 'desc', 'bca'],
    ['packets ascending', 'packets', 'asc', 'abc'],
    ['bytes descending', 'bytes', 'desc', 'cab'],
    ['rtt descending', 'rtt', 'desc', 'cab'],
    ['protocol ascending, ties busiest first', 'protocol', 'asc', 'bca'],
    ['status: healthy before slow', 'status', 'asc', 'bac'],
    ['flow ascending', 'flow', 'asc', 'abc'],
  ]
  for (const [name, k, d, want] of cases) await t.test(name, () => assert.equal(ids(k, d), want))
  await t.test('the input is not changed', () => assert.deepEqual(flows.map((f) => f.id), ['a', 'b', 'c']))
})
