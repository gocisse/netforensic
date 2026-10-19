package analyzer

import (
	"strings"

	"github.com/gocisse/netforensic/internal/models"
)

// The recommendations of Slow Server Response, chosen by the evidence in the
// response window (see slowResponseAdvice); slowRespAmbiguous is also the
// text used where no evidence is at hand.
const (
	slowRespRequestAcked = "The server's TCP stack acknowledged the request, but the first data came much later and no retransmission was captured in between. The delay is after the request arrived: look at the server (application processing, a slow backend or database, or an overloaded host), or at a proxy or load balancer in front of it."
	slowRespLoss         = "Retransmissions or duplicate ACKs were captured while waiting, so packet loss may explain the delay rather than slow processing. Fix the loss first (check the path, MTU and middleboxes, and compare with a capture at the server to see when the request arrived), then measure again."
	slowRespAmbiguous    = "The first server data came much later than the client's first data, but this capture cannot show whether the time went to the server or to the network (no acknowledgement of the request and no retransmission was captured). Capture at the server, or on both sides, to tell them apart."
	slowRespServerFirst  = "The server took this long to send its first data after the handshake. This capture cannot show whether the time went to the server or to the network (no retransmission was captured). Capture at the server, or on both sides, to tell them apart."

	// httpSlowAdvice is the single recommendation of HTTP Slow Response, whose
	// issue is not tied to a flow and so has no response-window evidence.
	httpSlowAdvice = "The server took more than a second to answer this request. The capture alone does not show whether the time went to the application or to packet loss on the path: check this flow for retransmissions first; if there are none, look at application and database performance on the server side."
)

// recommendations say what to look at or do about each kind of issue.
var issueRecommendations = map[string]string{
	titleFastRetransmit:            "A TCP segment was retransmitted after 3 or more duplicate ACKs for the same byte. Duplicate ACKs can follow a lost segment, but also reordering or delayed delivery, so this does not by itself prove packet loss. Compare captures at both ends to see whether the original segment reached the receiver.",
	titleTimeoutRetransmit:         "A TCP segment was retransmitted after a period without sufficient acknowledgment progress. This does not by itself prove packet loss or a path-wide stall. Compare captures at both ends to identify where the delay or missing acknowledgment occurs.",
	titleRetransmissions:           "Segments were sent again on this flow without a duplicate-ACK or silence trigger that NetForensic could identify. A retransmission does not by itself prove packet loss. Open the filter in Wireshark and compare the timing of the resent frames with their originals; compare with a capture at the other end.",
	titleZeroWindow:                "The receiver advertised a TCP receive window of 0, which asks the sender to pause sending data. This capture does not show why the window reached zero or how long the sender actually waited. Check how the receiving application reads from its socket and its buffer settings and load, and compare with a capture at the other end.",
	titleZeroWindowReset:           "A TCP receive window of 0 was advertised on this flow and the connection was later reset. This capture does not show whether the two are related, or who or what caused either. Use the filter to check their order, then inspect the applications and any device on the path.",
	titleRefused:                   "The server answered the SYN with an RST: nothing listens on that port, or a firewall actively rejects it. Check that the service is running and bound to the right address and port, and review firewall rules.",
	titleAborted:                   "A connection that was working was torn down with an RST instead of a normal close. Look at who sent the RST (the filter shows it) and why: an application crash, a timeout setting, a firewall or load balancer, or a server out of resources.",
	titleIdle:                      "An RST arrived long after the last data, which looks like an idle-timeout cleanup by a firewall, NAT or server. If connections need to stay open, enable TCP keepalives or raise the idle timeout.",
	titleStray:                     "RSTs arrived for connections the capture never saw, typically replies to a port scan or to segments of a connection the sender no longer knows. If the sources are unexpected, check for scanning; if the capture started late, this is harmless.",
	titleUnansweredSYN:             "SYNs got no reply in this capture. The cause cannot be told from here: a firewall dropping them, an unreachable server, or a capture point that does not see the replies (asymmetric routing). Capture at the server, or on both paths, to tell them apart.",
	titleSYNFlood:                  "Many connection attempts to one service went unanswered in a short time, the pattern of a SYN flood or of a service that cannot keep up. If the sources are many and spoofed-looking, consider SYN cookies and rate limiting; if the capture only sees one direction, the replies may simply have taken another path.",
	titleSYNRetried:                "The first SYN got no answer and the handshake only worked after a retry, which adds delay at connection setup. Look for packet loss or a slow server on the way to the destination.",
	"Slow TCP Handshake":           "The SYN to final ACK took too long. Look at the network round-trip time to the server and at the server's accept queue or load; compare the SYN-ACK delay with the ACK delay to see which end is slow.",
	"Slow Server Response":         slowRespAmbiguous,
	"High Network Latency":         "Round trips take longer than 200 ms, which points to a long or congested path, queueing (bufferbloat) or a distant server. Compare with a ping from the same place and check for a saturated link.",
	"High Jitter":                  "Round-trip times vary widely, with peaks above 500 ms. Look for bursts of traffic that fill a queue, a congested or shared link, or wireless interference.",
	"DNS NXDOMAIN":                 "The resolver says these names do not exist. Check for typos, stale configuration, a missing search domain or reverse-lookup zone, or software that queries names it should not.",
	"DNS SERVFAIL":                 "The resolver could not answer these queries. Check that the resolver is healthy and that its upstream servers or authoritative servers for the zone respond; DNSSEC validation failures also show up this way.",
	"DNS Timeout":                  "Queries got no answer within 5 seconds. Check that the resolver is reachable and responding on port 53 (UDP and TCP), look for a firewall dropping DNS, and try another resolver.",
	"DNS Slow Response":            "The resolver took more than a second to answer. Look at the resolver's load, its upstream latency and whether it answers from cache.",
	"HTTP Client Error":            "The server rejected the request (4xx): a wrong URL, missing credentials, or a request the server refuses. Compare with what the client was meant to send.",
	"HTTP Server Error":            "The server failed while handling the request (5xx). Look at the server's own logs for the same time; if only some requests fail, check the backends behind a load balancer.",
	"HTTP Slow Response":           httpSlowAdvice,
	"TLS Handshake Failure":        "The TLS handshake was rejected. Check that client and server share a protocol version and cipher suite, that the certificate is valid, trusted and matches the name, and that the client trusts the issuing CA.",
	"TLS Protocol Downgrade":       "The server chose an older TLS version than the client offered. Update the server's TLS configuration to support TLS 1.2 or later; a downgrade can also be a sign of interference on the path.",
	"ICMP Destination Unreachable": "A router or host reported that traffic could not be delivered. The reason (network, host, port unreachable or administratively prohibited) is in the description; check routing and firewall rules for those destinations.",
	"ICMP Time Exceeded":           "Packets ran out of TTL on the way. Look for a routing loop, or a traceroute: a few of these are normal, many from one router point to a loop.",
	"ICMP Redirect":                "A router told a host to use a different gateway. Check the host's routing table and the network design; redirects can also be abused to divert traffic.",
	"ARP Storm":                    "A burst of ARP requests, often a loop, a scan or a misbehaving host. Find the busiest sender (in the description) and check it and the switch topology for loops.",
	"Duplicate IP Address":         "Two devices claim the same IP address. Find both MAC addresses (in the description), then fix the addressing or the DHCP scope; this causes intermittent connectivity.",
	titleSIPRegistration:           "A phone or trunk could not register. Check the credentials, the registrar address and realm, and whether the account is allowed; 403 usually means wrong credentials or a blocked address, 404 an unknown user, 5xx a server problem.",
	titleSIPCallSetup:              "Calls could not be set up. The status code tells why: 486 busy, 404 not found, 480 unavailable, 503 server overloaded. Check the dial plan, the called party's registration and the trunk's capacity.",
	titleSIPErrorRate:              "More than a tenth of the SIP requests on this flow failed. Look at the failure codes in the filter's results and at the server's health; a steady error rate often means a misconfigured trunk or an overloaded server.",
	titleDHCPNak:                   "The server refused the client's request, usually because the address it asked for is not valid on this network (the client moved, or its lease was lost) or the pool is empty. Check the server's pool and leases, and the reason in the message; the client should then restart with a Discover.",
	titleDHCPExhaustion:            "One server keeps refusing requests: its address pool may be used up. Check free addresses in the scope, shorten the lease time, remove stale leases or enlarge the pool, and look for devices that request many addresses.",
	titleDHCPFailRate:              "Many requests are refused. Check the pools and leases of the servers named, any rogue or second DHCP server on the network, and the clients that fail.",
	titleDHCPTimeout:               "A Discover got no Offer. Check that a DHCP server or relay is reachable on this segment (UDP 67/68, broadcast), that no firewall or DHCP snooping blocks it, and whether the capture sees the server's side.",
	titleDHCPv6NoAddrs:             "The server has no address or prefix to give or no record of the client. Check the pool and prefix delegation size on the server, remove stale leases, and for NoBinding make the client restart with a Solicit.",
	titleDHCPv6Config:              "The server's answer does not fit the client's request: the client is on another link, must use multicast, or is not configured or allowed. Check the server's configuration for this client and link, and relay agent settings.",
	titleDHCPv6FailRate:            "The server rejects many requests. Check its pool, its configuration and the clients that fail; the status codes in the filter's results say why.",
	titleDHCPv6Timeout:             "Solicit or Request messages got no answer. Check that a DHCPv6 server or relay is reachable on this link (UDP 547, multicast ff02::1:2), that no firewall blocks it, and whether the capture sees the server's side.",
	titleQUICTimeout:               "The client sent a QUIC Initial and nothing came back. Check that UDP port 443 (or the service's port) is open end to end: many firewalls block UDP 443. Browsers fall back to TCP, so users may notice nothing.",
	titleQUICRetry:                 "The server asked the client to prove its address with a Retry, which costs an extra round trip. This is normal for servers under load or with address validation on, and not a fault.",
	titleQUICVersionNeg:            "The server did not support the version the client tried and offered others. Normal when a client probes or uses an old draft; if connections then succeed, nothing is wrong.",
	titleQUICDraft:                 "A client is using a draft version of QUIC, which current servers may no longer accept. Update the client software.",
}

// recommendationFor returns what to do about an issue, from its title.
func recommendationFor(is models.Issue) string {
	if r, ok := issueRecommendations[is.Title]; ok {
		return r
	}
	switch {
	case strings.HasPrefix(is.Title, "Unanswered SYN"):
		return issueRecommendations[titleUnansweredSYN]
	case strings.HasPrefix(is.Title, "Possible SYN Flood"):
		return issueRecommendations[titleSYNFlood]
	}
	return ""
}
