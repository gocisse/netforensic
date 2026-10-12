import assert from 'node:assert/strict'
import { test } from 'node:test'
import { groupBySeverity, impactOf } from './issueView.ts'
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
