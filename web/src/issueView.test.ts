import assert from 'node:assert/strict'
import { test } from 'node:test'
import { affectedIPs, impactOf, matchesIssueSearch, sortIssues } from './issueView.ts'
import type { Issue } from './types.ts'

const issue = (over: Partial<Issue>): Issue => ({ id: 'x', severity: 'INFO', category: 'TCP', title: 't', description: '', timestamp: '', ...over })

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


test('sortIssues', async (t) => {
  const issues = [
    issue({ id: 'w9', severity: 'WARNING', count: 9, title: 'b', protocols: ['UDP'] }),
    issue({ id: 'e2', severity: 'ERROR', count: 2, title: 'z', protocols: ['TCP'] }),
    issue({ id: 'e39', severity: 'ERROR', count: 39, title: 'a', protocols: ['TCP'] }),
    issue({ id: 'i', severity: 'INFO', title: 'c' }),
    issue({ id: 'c', severity: 'CRITICAL', count: 1, title: 'y', protocols: ['DNS'] }),
  ]
  const ids = (key: Parameters<typeof sortIssues>[1], dir: 'asc' | 'desc') => sortIssues(issues, key, dir).map((i) => i.id)
  const cases: { name: string; key: Parameters<typeof sortIssues>[1]; dir: 'asc' | 'desc'; want: string[] }[] = [
    { name: 'worst severity first, then the most events', key: 'severity', dir: 'desc', want: ['c', 'e39', 'e2', 'w9', 'i'] },
    { name: 'least severe first', key: 'severity', dir: 'asc', want: ['i', 'w9', 'e39', 'e2', 'c'] },
    { name: 'most events first', key: 'count', dir: 'desc', want: ['e39', 'w9', 'e2', 'c', 'i'] },
    { name: 'fewest events first; ties keep the default order', key: 'count', dir: 'asc', want: ['c', 'i', 'e2', 'w9', 'e39'] },
    { name: 'by title', key: 'title', dir: 'asc', want: ['e39', 'w9', 'i', 'c', 'e2'] },
    { name: 'by protocol; issues with none sort first when ascending', key: 'protocol', dir: 'asc', want: ['i', 'c', 'e39', 'e2', 'w9'] },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.deepEqual(ids(c.key, c.dir), c.want))
  }
  await t.test('the input is not changed', () => {
    const before = issues.map((i) => i.id)
    sortIssues(issues, 'title', 'desc')
    assert.deepEqual(issues.map((i) => i.id), before)
  })
})

test('matchesIssueSearch', async (t) => {
  const i = issue({
    severity: 'ERROR',
    title: 'Timeout Retransmit',
    description: 'flow 10.148.119.10:40534-128.227.1.184:1363 went silent',
    flow_id: '10.148.119.10:40534-128.227.1.184:1363',
    protocols: ['TCP'],
    occurrences: [{ time: '', subject: 'example.org' }],
  })
  const cases: [string, string, boolean][] = [
    ['empty search matches', '', true],
    ['by title, ignoring case', 'timeout', true],
    ['by address', '128.227.1.184', true],
    ['by address and port', '10.148.119.10:40534', true],
    ['by the subject of an event', 'EXAMPLE.org', true],
    ['by protocol', 'tcp', true],
    ['by severity', 'error', true],
    ['every word must match', 'timeout 9.9.9.9', false],
    ['all words, in any order', '128.227.1.184 timeout', true],
    ['no match', 'zero window', false],
  ]
  for (const [name, q, want] of cases) {
    await t.test(name, () => assert.equal(matchesIssueSearch(i, q), want))
  }
})

test('affectedIPs', async (t) => {
  const occ = (subject: string) => ({ time: '', subject })
  const cases: { name: string; issue: Issue; want: { labels: string[]; total: number } }[] = [
    { name: 'a single flow', issue: issue({ flow_id: '10.0.0.145:54436-186.15.230.24:80' }), want: { labels: ['10.0.0.145:54436 \u2192 186.15.230.24:80'], total: 1 } },
    {
      name: 'a target that is an end of the flow adds nothing',
      issue: issue({ flow_id: '10.0.2.15:58322-157.240.11.22:443', target: '157.240.11.22:443' }),
      want: { labels: ['10.0.2.15:58322 \u2192 157.240.11.22:443'], total: 1 },
    },
    {
      name: 'many flows: the first two and the count',
      issue: issue({ target: '10.253.96.89:80', occurrences: [occ('10.1.1.1:1-10.2.2.2:2'), occ('10.1.1.3:1-10.2.2.2:2'), occ('10.1.1.4:1-10.2.2.2:2')] }),
      want: { labels: ['10.253.96.89:80', '10.1.1.1:1 \u2192 10.2.2.2:2'], total: 4 },
    },
    { name: 'a resolver and the names it was asked', issue: issue({ target: '10.173.8.1', occurrences: [occ('a.example'), occ('b.example')] }), want: { labels: ['10.173.8.1', 'a.example'], total: 3 } },
    { name: 'a tunnel suffix is left out', issue: issue({ flow_id: '10.0.0.1:1-10.0.0.2:2@GRE:192.0.2.1~192.0.2.2' }), want: { labels: ['10.0.0.1:1 \u2192 10.0.0.2:2'], total: 1 } },
    { name: 'IPv6 gets brackets around the address when it has a port', issue: issue({ flow_id: '[2001:db8::1]:80-[2001:db8::2]:5000' }), want: { labels: ['[2001:db8::1]:80 \u2192 [2001:db8::2]:5000'], total: 1 } },
    { name: 'addresses are read from the description if no field names them', issue: issue({ description: 'host 10.0.0.9 sent to 10.0.0.145:80, again 10.0.0.9' }), want: { labels: ['10.0.0.9', '10.0.0.145:80'], total: 2 } },
    { name: 'not an address', issue: issue({ description: 'version 999.1.1.1 failed' }), want: { labels: [], total: 0 } },
    { name: 'nothing at all', issue: issue({}), want: { labels: [], total: 0 } },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.deepEqual(affectedIPs(c.issue), c.want))
  }
})
