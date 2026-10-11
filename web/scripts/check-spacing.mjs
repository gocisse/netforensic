// Checks that padding, margin, gap and space utilities use the spacing scale
// 4, 8, 12, 16, 24 and 32 px (Tailwind 1, 2, 3, 4, 6, 8), plus 0 and px.
// Usage: node scripts/check-spacing.mjs [--fix]
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ALLOWED = new Set(['0', 'px', '1', '2', '3', '4', '6', '8', 'auto', '22.5', '72.5'])
// What an off-scale value becomes with --fix: the nearest step on the scale.
const NEAREST = { '0.5': '1', '1.5': '2', '2.5': '3', '3.5': '4', '5': '6', '7': '8', '9': '8', '10': '8', '11': '8', '12': '8', '14': '8', '16': '8', '20': '8', '22.5': '8', '72.5': '8' }
const RE = /(?<![\w-])(-?)(p|px|py|pt|pr|pb|pl|m|mx|my|mt|mr|mb|ml|gap|gap-x|gap-y|space-x|space-y)-(\d+(?:\.\d+)?|px|auto)(?![\w.[-])/g

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) yield* files(p)
    else if (/\.(tsx|ts)$/.test(name) && !name.endsWith('.test.ts')) yield p
  }
}

const fix = process.argv.includes('--fix')
let bad = 0
for (const file of files('src')) {
  const text = readFileSync(file, 'utf8')
  let changed = false
  const out = text.replace(RE, (m, neg, prefix, value) => {
    if (ALLOWED.has(value)) return m
    bad++
    if (!fix) {
      const line = text.slice(0, text.indexOf(m)).split('\n').length
      console.log(`${file}:${line}: ${m} is off the 4/8/12/16/24/32 scale`)
      return m
    }
    changed = true
    return `${neg}${prefix}-${NEAREST[value] ?? '4'}`
  })
  if (fix && changed) writeFileSync(file, out)
}
console.log(fix ? `${bad} values moved onto the scale` : `${bad} off-scale values`)
process.exit(!fix && bad > 0 ? 1 : 0)
