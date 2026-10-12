import assert from 'node:assert/strict'
import { test } from 'node:test'
import { shellQuote, tsharkCommand } from './wireshark.ts'

test('tsharkCommand', async (t) => {
  const cases: { name: string; file: string; filter: string; head?: number; want: string }[] = [
    { name: 'without a limit', file: 'a.pcap', filter: 'tcp.analysis.retransmission', want: `tshark -r 'a.pcap' -Y 'tcp.analysis.retransmission'` },
    { name: 'with a limit', file: 'a.pcap', filter: 'dns.flags.rcode > 0', head: 22, want: `tshark -r 'a.pcap' -Y 'dns.flags.rcode > 0' | head -22` },
    { name: 'a zero limit is no limit', file: 'a.pcap', filter: 'tcp', head: 0, want: `tshark -r 'a.pcap' -Y 'tcp'` },
    { name: 'quotes in the name and filter are escaped', file: `it's.pcap`, filter: `dns.qry.name == "x'y"`, head: 5, want: `tshark -r 'it'\\''s.pcap' -Y 'dns.qry.name == "x'\\''y"' | head -5` },
  ]
  for (const c of cases) {
    await t.test(c.name, () => assert.equal(tsharkCommand(c.file, c.filter, c.head), c.want))
  }
})

test('shellQuote', () => assert.equal(shellQuote('a b'), `'a b'`))
