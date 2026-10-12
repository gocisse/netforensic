import assert from 'node:assert/strict'
import { test } from 'node:test'
import { groupBySeverity, impactOf, issueRows } from './issueView.ts'
import type { Issue } from './types.ts'

const issue = (over: Partial<Issue>): Issue => ({ id: 'x', severity: 'INFO', category: 'TCP', title: 't', description: '', timestamp: '', ...over })

test('groupBySeverity', async (t) => {
  const cases: { name: string; issues: Issue[]; want: [string, string[]][] }[] = [
    { name: 'empty', issues: [], want: [] },
    {
      name: 'worst severity first, empty severities left out',
      issues: [issue({ id: 'w', severity: 'WARNING' }), issue({ id: 'i', severity: 'INFO' }), issue({ id: 'e', severity: 'ERROR' }), issue({ id: 'c', severity: 'CRITICAL' })],
      want: [['CRITICAL', ['c']], ['ERROR', ['e']], ['WARNING', ['w']], ['INFO', ['i']]],
    },
    {
      name: 'within a group the bigger issue comes first, then by title',
      issues: [issue({ id: 'a', severity: 'ERROR', count: 2, title: 'b' }), issue({ id: 'b', severity: 'ERROR', count: 9 }), issue({ id: 'c', severity: 'ERROR', count: 2, title: 'a' })],
      want: [['ERROR', ['b', 'c', 'a']]],
    },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.deepEqual(groupBySeverity(c.issues).map((g) => [g.severity, g.issues.map((i) => i.id)]), c.want))
  }
})

test('impactOf', async (t) => {
  const occ = (subject: string) => ({ time: '', subject })
  const cases: { name: string; issue: Issue; want: string }[] = [
    { name: 'no events and nothing named', issue: issue({}), want: '1 event' },
    { name: 'a count without names', issue: issue({ count: 22 }), want: '22 events' },
    { name: 'flows are counted once each', issue: issue({ count: 3, flow_id: '10.0.0.1:1000-10.0.0.2:80', occurrences: [occ('10.0.0.1:1000-10.0.0.2:80'), occ('10.0.0.3:1000-10.0.0.2:80')] }), want: '3 events across 2 flows' },
    { name: 'domains are other targets', issue: issue({ count: 2, occurrences: [occ('a.example'), occ('b.example')] }), want: '2 events across 2 other targets' },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.equal(impactOf(c.issue), c.want))
  }
})

test('issueRows puts a heading before the issues of each group', () => {
  const rows = issueRows(groupBySeverity([issue({ id: 'w', severity: 'WARNING' }), issue({ id: 'e1', severity: 'ERROR', count: 5 }), issue({ id: 'e2', severity: 'ERROR' })]))
  assert.deepEqual(
    rows.map((r) => (r.kind === 'heading' ? `${r.severity}:${r.count}` : r.issue.id)),
    ['ERROR:2', 'e1', 'e2', 'WARNING:1', 'w'],
  )
  assert.deepEqual(issueRows([]), [])
})

test('groupBySeverity is linear: a hundred thousand issues group at once', () => {
  const many = Array.from({ length: 100_000 }, (_, n) => issue({ id: String(n), severity: n % 2 ? 'ERROR' : 'WARNING', count: n % 7 }))
  const t0 = performance.now()
  const groups = groupBySeverity(many)
  assert.equal(groups.length, 2)
  assert.equal(groups[0].issues.length + groups[1].issues.length, 100_000)
  assert.ok(performance.now() - t0 < 2000, 'grouping took too long')
})
