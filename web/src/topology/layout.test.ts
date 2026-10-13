import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ForceLayout } from './layout.ts'

const dist = (l: ForceLayout, i: number, j: number) => Math.hypot(l.x[i] - l.x[j], l.y[i] - l.y[j])

test('an empty graph is settled', () => {
  const l = new ForceLayout([], [])
  assert.ok(l.tick())
  assert.ok(l.done)
})

test('the layout is deterministic', () => {
  const make = () => {
    const l = new ForceLayout([10, 8, 6, 6, 5], [{ a: 0, b: 1 }, { a: 0, b: 2 }, { a: 1, b: 3 }, { a: 2, b: 4 }])
    l.settle()
    return [...l.x, ...l.y]
  }
  assert.deepEqual(make(), make())
})

test('it settles, and every position is a finite number', () => {
  const radii = Array.from({ length: 200 }, (_, i) => 5 + (i % 7))
  const edges = Array.from({ length: 199 }, (_, i) => ({ a: 0, b: i + 1 }))
  const l = new ForceLayout(radii, edges)
  l.settle()
  assert.ok(l.done, 'it ran to rest')
  for (let i = 0; i < 200; i++) assert.ok(Number.isFinite(l.x[i]) && Number.isFinite(l.y[i]))
})

test('nodes do not sit on top of each other', () => {
  const radii = Array.from({ length: 60 }, () => 8)
  const edges = Array.from({ length: 59 }, (_, i) => ({ a: 0, b: i + 1 })) // a star
  const l = new ForceLayout(radii, edges)
  l.settle()
  let closest = Infinity
  for (let i = 0; i < 60; i++) for (let j = i + 1; j < 60; j++) closest = Math.min(closest, dist(l, i, j))
  assert.ok(closest > 8, `the closest pair is ${closest.toFixed(1)} apart`)
})

test('joined nodes end up about a rest length apart, and a chain stretches out', () => {
  // the rest length of two nodes of radius 8 is 8 + 8 + 60
  const pair = new ForceLayout([8, 8], [{ a: 0, b: 1 }])
  pair.settle()
  assert.ok(Math.abs(dist(pair, 0, 1) - 76) < 30, `${dist(pair, 0, 1).toFixed(1)} apart`)

  const chain = new ForceLayout([8, 8, 8, 8, 8], [{ a: 0, b: 1 }, { a: 1, b: 2 }, { a: 2, b: 3 }, { a: 3, b: 4 }])
  chain.settle()
  assert.ok(dist(chain, 0, 1) < dist(chain, 0, 4), 'the ends are further apart than neighbors')
  assert.ok(dist(chain, 3, 4) < dist(chain, 0, 4))
})

test('two nodes at the same spot are pushed apart rather than into NaN', () => {
  const l = new ForceLayout([8, 8], [])
  l.x[1] = l.x[0]
  l.y[1] = l.y[0]
  l.settle()
  assert.ok(dist(l, 0, 1) > 0)
  assert.ok(Number.isFinite(l.x[0]))
})

test('a thousand nodes settle quickly', () => {
  const radii = Array.from({ length: 1000 }, (_, i) => 5 + (i % 10))
  const edges = Array.from({ length: 1500 }, (_, i) => ({ a: i % 1000, b: (i * 7 + 1) % 1000 })).filter((e) => e.a !== e.b)
  const t0 = performance.now()
  new ForceLayout(radii, edges).settle()
  assert.ok(performance.now() - t0 < 5000, 'took too long')
})
