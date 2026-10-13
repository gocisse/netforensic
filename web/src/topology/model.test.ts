import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  MAX_RADIUS,
  MAX_ZOOM,
  MIN_RADIUS,
  MIN_ZOOM,
  busyThreshold,
  circleInView,
  edgeProtocols,
  edgeSeverities,
  edgeVisible,
  edgeWidth,
  fitView,
  formatVolume,
  hitTest,
  issuesForIp,
  nodeMatches,
  nodeRadius,
  nodeTone,
  segmentInView,
  visibleParts,
  worthShowing,
  zoomAt,
} from './model.ts'
import type { Flow, Issue, Topology, TopologyEdge, TopologyNode } from '../types.ts'

const node = (ip: string, over: Partial<TopologyNode> = {}): TopologyNode => ({ ip, type: 'client', traffic_volume: 100, packets: 1, issue_count: 0, is_problematic: false, protocols: [], ...over })
const edge = (source: string, target: string, over: Partial<TopologyEdge> = {}): TopologyEdge => ({ source, target, packets: 1, bytes: 100, issues: 0, protocol: 'TCP', ...over })
const issue = (over: Partial<Issue>): Issue => ({ id: 'x', severity: 'ERROR', category: 'TCP', title: 't', description: '', timestamp: '', ...over })

test('nodeRadius grows with traffic, between the limits', async (t) => {
  const cases: [string, number, number, number][] = [
    ['no traffic at all', 0, 100, MIN_RADIUS],
    ['no maximum', 50, 0, MIN_RADIUS],
    ['the busiest', 100, 100, MAX_RADIUS],
    ['more than the maximum is capped', 500, 100, MAX_RADIUS],
  ]
  for (const [name, v, max, want] of cases) await t.test(name, () => assert.equal(nodeRadius(v, max), want))
  await t.test('a quarter of the traffic is halfway up (square root)', () => assert.equal(nodeRadius(25, 100), MIN_RADIUS + (MAX_RADIUS - MIN_RADIUS) / 2))
  await t.test('busier is bigger', () => assert.ok(nodeRadius(60, 100) > nodeRadius(10, 100)))
})

test('edgeWidth', () => {
  assert.equal(edgeWidth(0, 100), 1)
  assert.equal(edgeWidth(100, 100), 6)
  assert.equal(edgeWidth(25, 100), 3.5)
  assert.equal(edgeWidth(5, 0), 1)
})

test('busyThreshold and nodeTone', async (t) => {
  const nodes = Array.from({ length: 20 }, (_, i) => node(`10.0.0.${i}`, { traffic_volume: (i + 1) * 100 }))
  const busy = busyThreshold(nodes)
  await t.test('the busiest tenth is busy', () => assert.equal(busy, 1900))
  await t.test('a graph of fewer than five nodes has no busy node', () => assert.equal(busyThreshold(nodes.slice(0, 4)), Infinity))
  const cases: [string, TopologyNode, string][] = [
    ['issues make a node red, however busy', node('a', { is_problematic: true, traffic_volume: 99999 }), 'problem'],
    ['an address with issues and no traffic is red', node('a', { is_problematic: true, traffic_volume: 0 }), 'problem'],
    ['heavy traffic is yellow', node('a', { traffic_volume: 1900 }), 'busy'],
    ['light traffic is green', node('a', { traffic_volume: 500 }), 'ok'],
    ['no traffic is green', node('a', { traffic_volume: 0 }), 'ok'],
  ]
  for (const [name, n, want] of cases) await t.test(name, () => assert.equal(nodeTone(n, busy), want))
  await t.test('nothing is busy when there is no threshold', () => assert.equal(nodeTone(node('a', { traffic_volume: 10 ** 9 }), Infinity), 'ok'))
})

test('protocol and severity lists', () => {
  const topo: Topology = {
    nodes: [],
    edges: [edge('a', 'b', { protocol: 'DNS' }), edge('a', 'c', { protocol: 'TCP', issues: 1, worst_severity: 'WARNING' }), edge('a', 'd', { protocol: 'DNS', issues: 2, worst_severity: 'ERROR' }), edge('a', 'e', { protocol: '' })],
    total_nodes: 5,
    total_edges: 4,
    truncated: false,
  }
  assert.deepEqual(edgeProtocols(topo), [{ protocol: 'DNS', edges: 2 }, { protocol: 'Other', edges: 1 }, { protocol: 'TCP', edges: 1 }])
  assert.deepEqual(edgeSeverities(topo), ['ERROR', 'WARNING'])
})

test('filters decide which edges and nodes are shown', async (t) => {
  const topo: Topology = {
    nodes: [node('a'), node('b'), node('c'), node('d'), node('lonely')],
    edges: [
      edge('a', 'b', { protocol: 'DNS' }),
      edge('a', 'c', { protocol: 'TCP', issues: 1, worst_severity: 'WARNING' }),
      edge('c', 'd', { protocol: 'TCP', issues: 1, worst_severity: 'ERROR' }),
    ],
    total_nodes: 5,
    total_edges: 3,
    truncated: false,
  }
  const all = { protocols: new Set(['DNS', 'TCP']), severities: new Set(['ERROR', 'WARNING'] as const) }
  await t.test('everything passes', () => {
    const v = visibleParts(topo, all)
    assert.equal(v.edges.size, 3)
    assert.deepEqual([...v.nodes].sort(), ['a', 'b', 'c', 'd', 'lonely'])
  })
  await t.test('a protocol that is off hides its edges, and the nodes only they joined', () => {
    const v = visibleParts(topo, { ...all, protocols: new Set(['TCP']) })
    assert.equal(v.edges.size, 2)
    assert.ok(!v.nodes.has('b'))
    assert.ok(v.nodes.has('a'), 'a is still on a TCP edge')
  })
  await t.test('a severity that is off hides the edges with that worst severity only', () => {
    const v = visibleParts(topo, { ...all, severities: new Set(['ERROR'] as const) })
    assert.deepEqual([...v.edges].map((e) => e.target).sort(), ['b', 'd'])
  })
  await t.test('an edge without issues does not depend on the severities', () => {
    assert.ok(edgeVisible(topo.edges[0], { protocols: new Set(['DNS']), severities: new Set() }))
  })
  await t.test('nothing shown but the nodes with no edges at all', () => {
    const v = visibleParts(topo, { protocols: new Set(), severities: new Set() })
    assert.equal(v.edges.size, 0)
    assert.deepEqual([...v.nodes], ['lonely'])
  })
})

test('nodeMatches', () => {
  const n = node('10.152.9.52', { type: 'dns_server' })
  assert.ok(nodeMatches(n, '152.9'))
  assert.ok(nodeMatches(n, ' 10.152 '))
  assert.ok(nodeMatches(n, 'dns server'))
  assert.ok(!nodeMatches(n, '10.153'))
  assert.ok(!nodeMatches(n, ''), 'an empty search matches nothing')
  assert.ok(!nodeMatches(n, '   '))
})

test('issuesForIp', async (t) => {
  const issues = [
    issue({ id: 'flow', flow_id: '10.0.0.1:1000-10.0.0.2:80' }),
    issue({ id: 'target', target: '10.0.0.2:80' }),
    issue({ id: 'bare', target: '10.0.0.2' }),
    issue({ id: 'event', occurrences: [{ time: '', subject: '10.0.0.3:5-10.0.0.2:53' }] }),
    issue({ id: 'name', occurrences: [{ time: '', subject: 'example.org' }] }),
    issue({ id: 'v6', flow_id: '[2001:db8::1]:1-[2001:db8::2]:2' }),
    issue({ id: 'other', flow_id: '10.0.0.8:1-10.0.0.9:2' }),
  ]
  const ids = (ip: string) => issuesForIp(issues, ip).map((i) => i.id)
  await t.test('both ends of a flow', () => {
    assert.deepEqual(ids('10.0.0.1'), ['flow'])
    assert.deepEqual(ids('10.0.0.2'), ['flow', 'target', 'bare', 'event'])
  })
  await t.test('the subject of an event', () => assert.deepEqual(ids('10.0.0.3'), ['event']))
  await t.test('IPv6 in any spelling', () => {
    assert.deepEqual(ids('2001:db8::2'), ['v6'])
    assert.deepEqual(ids('2001:0db8:0:0:0:0:0:1'), ['v6'])
  })
  await t.test('an address nobody names', () => assert.deepEqual(ids('10.9.9.9'), []))
  await t.test('something that is not an address', () => assert.deepEqual(ids('example.org'), []))
})

test('worthShowing', async (t) => {
  const flow = (src: string, dst: string, bytes: number): Flow => ({ id: `${src}-${dst}`, src_ip: src, dst_ip: dst, src_port: 1, dst_port: 2, protocol: 'TCP', packet_count: 1, bytes_sent: bytes, bytes_recv: 0 }) as Flow
  await t.test('issues are enough', () => assert.ok(worthShowing(1, [])))
  await t.test('no issues and few flows', () => assert.ok(!worthShowing(0, [flow('a', 'b', 10), flow('c', 'd', 10)])))
  await t.test('no issues and traffic spread evenly over many pairs', () => {
    const flows = Array.from({ length: 20 }, (_, i) => flow(`10.0.0.${i}`, `10.1.0.${i}`, 100))
    assert.ok(!worthShowing(0, flows))
  })
  await t.test('no issues but one address carries it all (a DNS server)', () => {
    const flows = Array.from({ length: 10 }, (_, i) => flow(`10.0.0.${i}`, '10.0.0.53', 100))
    assert.ok(worthShowing(0, flows))
  })
  await t.test('flows without bytes', () => assert.ok(!worthShowing(0, [flow('a', 'b', 0), flow('a', 'c', 0), flow('a', 'd', 0)])))
})

test('zoomAt keeps the point under the pointer where it is', async (t) => {
  const v = { x: 100, y: 50, k: 1 }
  const z = zoomAt(v, 2, 200, 100)
  await t.test('the world point under (200, 100) is the same', () => {
    assert.equal(v.x + 200 / v.k, z.x + 200 / z.k)
    assert.equal(v.y + 100 / v.k, z.y + 100 / z.k)
    assert.equal(z.k, 2)
  })
  await t.test('the zoom is limited', () => {
    assert.equal(zoomAt(v, 1e6, 0, 0).k, MAX_ZOOM)
    assert.equal(zoomAt(v, 1e-6, 0, 0).k, MIN_ZOOM)
  })
  await t.test('at the limit nothing moves', () => {
    const max = { x: 3, y: 4, k: MAX_ZOOM }
    assert.equal(zoomAt(max, 2, 10, 10), max)
  })
})

test('fitView shows all the points', async (t) => {
  const points = [{ x: -100, y: -50, r: 10 }, { x: 300, y: 150, r: 10 }]
  const v = fitView(points, 800, 400)
  await t.test('every point is inside the canvas', () => {
    for (const p of points) assert.ok(circleInView(p.x, p.y, p.r, v, 800, 400))
  })
  await t.test('it is centered', () => {
    const cx = ((100 - v.x) * v.k + 0) // the middle of the box is x = 100, y = 50
    assert.ok(Math.abs(cx - 400) < 1e-6)
  })
  await t.test('a single point is not magnified beyond 2', () => assert.equal(fitView([{ x: 0, y: 0, r: 5 }], 800, 400).k, 2))
  await t.test('nothing to fit', () => assert.deepEqual(fitView([], 800, 400), { x: 0, y: 0, k: 1 }))
  await t.test('no room', () => assert.deepEqual(fitView(points, 0, 0), { x: 0, y: 0, k: 1 }))
})

test('culling', async (t) => {
  const v = { x: 0, y: 0, k: 2 } // the canvas shows world x from 0 to 400 and y from 0 to 300
  const cases: [string, number, number, number, boolean][] = [
    ['inside', 100, 100, 5, true],
    ['just outside on the right', 410, 100, 5, false],
    ['partly in on the right: its edge reaches in', 403, 100, 5, true],
    ['far left', -500, 100, 5, false],
    ['below', 100, 400, 5, false],
  ]
  for (const [name, x, y, r, want] of cases) await t.test(name, () => assert.equal(circleInView(x, y, r, v, 800, 600), want))
  await t.test('a segment that crosses the canvas is in view although its ends are not', () => assert.ok(segmentInView(-1000, 100, 1000, 100, v, 800, 600)))
  await t.test('a segment beside it is not', () => assert.ok(!segmentInView(500, 0, 500, 400, v, 800, 600)))
})

test('hitTest finds the node under the pointer', async (t) => {
  const xs = [0, 100, 105], ys = [0, 0, 0], rs = [10, 10, 10]
  const v = { x: -50, y: -50, k: 1 }
  const all = () => true
  await t.test('on a node', () => assert.equal(hitTest(xs, ys, rs, all, v, 50, 50), 0)) // world (0, 0)
  await t.test('beside it', () => assert.equal(hitTest(xs, ys, rs, all, v, 70, 50), -1))
  await t.test('of two overlapping nodes, the nearer one', () => assert.equal(hitTest(xs, ys, rs, all, v, 150 + 4, 50), 2))
  await t.test('hidden nodes cannot be hit', () => assert.equal(hitTest(xs, ys, rs, (i) => i !== 0, v, 50, 50), -1))
  await t.test('a small node stays hittable when zoomed out', () => {
    const far = { x: -50, y: -50, k: 0.1 } // a radius of 10 is 1 px
    assert.equal(hitTest(xs, ys, rs, all, far, 5 + 3, 5), 0) // 3 px off the middle of node 0
  })
})

test('formatVolume', () => {
  assert.equal(formatVolume(0), '0 B')
  assert.equal(formatVolume(1023), '1023 B')
  assert.equal(formatVolume(1536), '1.5 KB')
  assert.equal(formatVolume(5 * 1024 * 1024), '5.0 MB')
  assert.equal(formatVolume(300 * 1024 * 1024), '300 MB')
  assert.equal(formatVolume(2 ** 50), '1024 TB')
})
