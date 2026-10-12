import assert from 'node:assert/strict'
import { test } from 'node:test'
import { AnalysisAssembler, parseLines } from './stream.ts'
import type { ChunkEvent, SummaryData } from './stream.ts'
import type { Flow, Issue } from '../types.ts'

const issue = (id: string): Issue => ({ id, severity: 'ERROR', category: 'TCP', title: id, description: '', timestamp: '' })
const flow = (id: string, issues = 0): Flow => ({
  id, src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, protocol: 'TCP', start_time: '', end_time: '', packet_count: 1, bytes_sent: 0, bytes_recv: 0, retransmits: 0,
  setup_time_ms: 0, ttfb_ms: 0, avg_rtt_ms: 0, max_rtt_ms: 0, issue_count: issues,
})
const summary = (issues: number, flows: number): ChunkEvent => ({
  chunk: 'summary',
  data: {
    file_name: 'x.pcap', total_packets: 10, total_flows: flows, analysis_time: '', duration: '1s', analysis_id: 'abc', good_traffic_filter: '!(a)',
    diagnosis: { health_score: 42, primary_cause: 'c', confidence: 'high', summary: '', timeline: [], recommendations: [] },
    counts: { issues, reportable_issues: issues, flows, healthy_flows: 1 },
  } satisfies SummaryData,
})

test('parseLines handles lines split across chunks', async (t) => {
  const cases: { name: string; carry: string; text: string; lines: string[]; rest: string }[] = [
    { name: 'whole lines', carry: '', text: '{"a":1}\n{"b":2}\n', lines: ['{"a":1}', '{"b":2}'], rest: '' },
    { name: 'a line cut in two', carry: '', text: '{"a":1}\n{"b"', lines: ['{"a":1}'], rest: '{"b"' },
    { name: 'the rest of a cut line', carry: '{"b"', text: ':2}\n', lines: ['{"b":2}'], rest: '' },
    { name: 'no newline yet', carry: '{"a"', text: ':1', lines: [], rest: '{"a":1' },
    { name: 'blank lines are dropped', carry: '', text: '\n{"a":1}\n\n', lines: ['{"a":1}'], rest: '' },
    { name: 'nothing', carry: '', text: '', lines: [], rest: '' },
  ]
  for (const c of cases) {
    await t.test(c.name, () => {
      const r = parseLines(c.carry, c.text)
      assert.deepEqual(r.lines, c.lines)
      assert.equal(r.carry, c.rest)
    })
  }
})

test('the assembler builds an analysis from its chunks', () => {
  const a = new AnalysisAssembler()
  assert.equal(a.snapshot(), null)
  assert.equal(a.started, false)

  assert.equal(a.apply(summary(3, 3)), 'summary')
  assert.equal(a.started, true)
  let s = a.snapshot()!
  assert.equal(s.diagnosis.health_score, 42, 'the verdict is there at once')
  assert.deepEqual(s.issues, [])
  assert.deepEqual(a.progress(), { issues: { loaded: 0, total: 3 }, flows: { loaded: 0, total: 3 } })
  assert.equal(a.issuesDone, false)

  a.apply({ chunk: 'overview', data: { protocol_stats: [], top_talkers: [flow('t')], slow_flows: [] } })
  assert.equal(a.snapshot()!.top_talkers.length, 1)

  a.apply({ chunk: 'issues', offset: 0, data: [issue('1'), issue('2')] })
  assert.equal(a.issuesLoaded, 2)
  assert.equal(a.issuesDone, false)
  s = a.snapshot()!
  assert.deepEqual(s.issues.map((i) => i.id), ['1', '2'])
  a.apply({ chunk: 'issues', offset: 2, data: [issue('3')] })
  assert.equal(a.issuesDone, true)
  assert.equal(a.snapshot()!.issues.length, 3)
  assert.equal(s.issues.length, 2, 'an earlier snapshot is not changed by later batches')

  a.apply({ chunk: 'flows', offset: 0, data: [flow('a', 1), flow('b')] })
  assert.equal(a.flowsDone, false)
  assert.deepEqual(a.snapshot()!.flows, [], 'flows are given out only when all are there')
  a.apply({ chunk: 'flows', offset: 2, data: [flow('c', 2)] })
  assert.equal(a.flowsDone, true)
  s = a.snapshot()!
  assert.deepEqual(s.flows!.map((f) => f.id), ['a', 'b', 'c'])
  assert.deepEqual(s.healthy_flows!.map((f) => f.id), ['b'], 'the healthy flows are those no issue names')
  assert.equal(a.apply({ chunk: 'done' }), 'done')
})

test('an analysis without issues or flows is complete once the summary is in', () => {
  const a = new AnalysisAssembler()
  a.apply(summary(0, 0))
  assert.equal(a.issuesDone, true)
  assert.equal(a.flowsDone, true)
  assert.deepEqual(a.snapshot()!.healthy_flows, [])
})

test('done completes a stream that ended short of its counts', () => {
  const a = new AnalysisAssembler()
  a.apply(summary(5, 5))
  a.apply({ chunk: 'issues', offset: 0, data: [issue('1')] })
  a.apply({ chunk: 'done' })
  assert.equal(a.issuesDone, true)
  assert.equal(a.flowsDone, true)
})

test('a hundred thousand issues and flows assemble quickly', () => {
  const a = new AnalysisAssembler()
  a.apply(summary(100_000, 100_000))
  const t0 = performance.now()
  for (let off = 0; off < 100_000; off += 100) a.apply({ chunk: 'issues', offset: off, data: Array.from({ length: 100 }, (_, i) => issue(String(off + i))) })
  for (let off = 0; off < 100_000; off += 500) a.apply({ chunk: 'flows', offset: off, data: Array.from({ length: 500 }, (_, i) => flow(String(off + i), i % 2)) })
  const s = a.snapshot()!
  assert.equal(s.issues.length, 100_000)
  assert.equal(s.healthy_flows!.length, 50_000)
  assert.ok(performance.now() - t0 < 3000)
})
