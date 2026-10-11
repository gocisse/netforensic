# netforensic

A command-line forensic tool for `.pcap` and `.pcapng` captures. It reads a
capture, follows flows, and reports what went wrong: retransmissions, resets,
unanswered SYNs, zero windows, DNS and ICMP failures, slow handshakes and
responses, with a root-cause summary.

```
go build -o netforensic ./cmd/netforensic
./netforensic capture.pcapng                 # triage report
./netforensic -o json capture.pcapng         # every issue, machine-readable
./netforensic --follow "10.0.0.1:5000-10.0.0.2:80" capture.pcapng          # reconstructed stream
./netforensic --follow-packets "10.0.0.1:5000-10.0.0.2:80" capture.pcapng  # packet by packet
```

## Known limitations

- **Tunnels.** Captures containing GRE or IP-in-IP tunnels may show inflated
  flow and retransmit counts, because the inner traffic is aggregated by the
  outer IP addresses and the inner ports. Full tunnel decapsulation is planned
  for a future release. (For example, `The-Ultimate-PCAP.pcapng` reports about
  three times the retransmissions that Wireshark does.)
- **One-sided captures.** A capture point that sees only one direction of a
  conversation (asymmetric routing, a SPAN port on one link) cannot show
  replies. Such SYNs are reported as "Unanswered SYN (No reply captured ...)"
  without claiming a cause.
- **Health score.** It starts at 100 and drops with every issue. It goes below
  0 for badly troubled captures and stops at -50 (CATASTROPHIC).
