import assert from 'node:assert/strict'
import { test } from 'node:test'
import { splitMono } from './monoText.ts'

const monos = (s: string) => splitMono(s).filter((p) => p.mono).map((p) => p.text)

test('splitMono', async (t) => {
  const cases: { name: string; text: string; want: string[] }[] = [
    { name: 'plain prose has nothing', text: 'The sender waited for a retransmission timeout', want: [] },
    { name: 'an IPv4 address', text: 'Resolver 10.173.8.34 returned SERVFAIL', want: ['10.173.8.34'] },
    { name: 'an IPv4 address with a port', text: 'to 10.253.96.89:80 got no SYN', want: ['10.253.96.89:80'] },
    { name: 'both ends of a flow', text: 'flow 10.22.47.52:53875-128.200.110.181:8080 was reset', want: ['10.22.47.52:53875', '128.200.110.181:8080'] },
    { name: 'a time is not an address', text: 'first seq 75037719 at 13:13:59.155; waited', want: [] },
    { name: 'a version number is not an address', text: 'TLS 1.2 and QUIC 0.1.2 drafts', want: [] },
    { name: 'a full IPv6 address', text: 'from 2001:db8:0:0:0:0:0:1 to somewhere', want: ['2001:db8:0:0:0:0:0:1'] },
    { name: 'a short IPv6 address', text: 'from fe80::1 to 2001:db8::ff00:42:8329 failed', want: ['fe80::1', '2001:db8::ff00:42:8329'] },
    { name: 'a bracketed IPv6 address with a port', text: 'client [2001:db8::1]:547 asked', want: ['[2001:db8::1]:547'] },
    { name: 'a reverse-lookup name', text: 'Top domains: 1.1.168.192.in-addr.arpa (2), example.com', want: ['1.1.168.192.in-addr.arpa'] },
    { name: 'a reverse-lookup name with a domain after it', text: 'Top: 1.16.254.10.in-addr.arpa.srv.example.intra (1), b', want: ['1.16.254.10.in-addr.arpa.srv.example.intra'] },
    { name: 'a port after the word port', text: 'nothing listens on port 8443 here', want: ['8443'] },
    { name: 'several ports', text: 'probed ports 22, 80, 443 in turn', want: ['22, 80, 443'] },
    { name: 'a number elsewhere is not a port', text: 'retransmitted 25 segments', want: [] },
    { name: 'an address at the start and end of the text', text: '10.0.0.1 talked to 10.0.0.2', want: ['10.0.0.1', '10.0.0.2'] },
  ]
  for (const c of cases) {
    await t.test(c.name, () => {
      assert.deepEqual(monos(c.text), c.want)
      assert.equal(splitMono(c.text).map((p) => p.text).join(''), c.text, 'the pieces make up the text again')
    })
  }
})
