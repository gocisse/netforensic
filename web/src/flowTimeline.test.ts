import assert from 'node:assert/strict'
import { test } from 'node:test'
import { clockTime, firstIssueOf, flowDuration, flowFilter, issuesForFlow, problemFlows, sinceStart } from './flowTimeline.ts'
import type { Flow, Issue } from './types.ts'

const flow = (over: Partial<Flow>): Flow => ({
  id: '10.0.0.1:5000-10.0.0.2:443',
  src_ip: '10.0.0.1',
  dst_ip: '10.0.0.2',
  src_port: 5000,
  dst_port: 443,
  protocol: 'TCP',
  start_time: '2024-01-01T13:13:52.000Z',
  end_time: '2024-01-01T13:13:53.250Z',
  packet_count: 10,
  bytes_sent: 0,
  bytes_recv: 0,
  retransmits: 0,
  setup_time_ms: 0,
  ttfb_ms: 0,
  avg_rtt_ms: 0,
  max_rtt_ms: 0,
  ...over,
})
const issue = (over: Partial<Issue>): Issue => ({ id: 'x', severity: 'ERROR', category: 'TCP', title: 't', description: '', timestamp: '', ...over })

test('flowFilter', async (t) => {
  const cases: { name: string; flow: Flow; want: string }[] = [
    { name: 'the stream number when known', flow: flow({ tcp_stream: 219 }), want: 'tcp.stream eq 219' },
    { name: 'stream 0 is a stream', flow: flow({ tcp_stream: 0 }), want: 'tcp.stream eq 0' },
    { name: 'addresses when it is not', flow: flow({}), want: 'ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 5000 && tcp.port == 443' },
    {
      name: 'IPv6 addresses',
      flow: flow({ src_ip: '2001:db8::1', dst_ip: '2001:db8::2' }),
      want: 'ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2 && tcp.port == 5000 && tcp.port == 443',
    },
  ]
  for (const c of cases) await t.test(c.name, () => assert.equal(flowFilter(c.flow), c.want))
})

test('clockTime and sinceStart', async (t) => {
  assert.equal(clockTime('2024-01-01T13:13:59.155Z'), '13:13:59.155')
  assert.equal(clockTime('nonsense'), 'nonsense')
  const cases: [string, string][] = [
    ['2024-01-01T13:13:52.000Z', '+0 ms'],
    ['2024-01-01T13:13:52.808Z', '+808 ms'],
    ['2024-01-01T13:13:53.250Z', '+1.250 s'],
    ['2024-01-01T13:15:57.000Z', '+2 min 5 s'],
    ['2024-01-01T13:13:51.000Z', '+0 ms'], // never negative
  ]
  for (const [at, want] of cases) await t.test(want, () => assert.equal(sinceStart(at, '2024-01-01T13:13:52.000Z'), want))
  assert.equal(flowDuration(flow({})), '1.250 s')
})

test('issuesForFlow matches the flow by its ID in any field', () => {
  const mine = flow({})
  const issues = [
    issue({ id: 'a', flow_id: mine.id }),
    issue({ id: 'b', occurrences: [{ time: '', subject: mine.id }] }),
    issue({ id: 'c', flow_id: '10.0.0.9:1-10.0.0.8:2' }),
    issue({ id: 'd' }),
  ]
  assert.deepEqual(issuesForFlow(issues, mine).map((i) => i.id), ['a', 'b'])
})

test('problemFlows lists flows with issues, worst first', () => {
  const fs = [
    flow({ id: 'ok', issue_count: 0, status: 'working' }),
    flow({ id: 'slow-big', issue_count: 1, status: 'slow', packet_count: 99 }),
    flow({ id: 'broken-small', issue_count: 1, status: 'broken', packet_count: 2 }),
    flow({ id: 'broken-many', issue_count: 3, status: 'broken', packet_count: 1 }),
  ]
  assert.deepEqual(problemFlows(fs, 10).map((f) => f.id), ['broken-many', 'broken-small', 'slow-big'])
  assert.deepEqual(problemFlows(fs, 1).map((f) => f.id), ['broken-many'])
  assert.deepEqual(problemFlows([], 5), [])
})

test('firstIssueOf finds the marked event', () => {
  const ev = (event: string, first?: boolean) => ({ timestamp: '', event, severity: 'ERROR' as const, description: '', first_issue: first })
  assert.equal(firstIssueOf(flow({ timeline: [ev('a'), ev('b', true), ev('c', true)] }))?.event, 'b')
  assert.equal(firstIssueOf(flow({ timeline: [ev('a')] })), undefined)
  assert.equal(firstIssueOf(flow({})), undefined)
})
