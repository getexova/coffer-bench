package authapi

import (
	"net"
	"net/http"
	"strings"
)

// SourceIP resolves the client address recorded on every audit event and used as
// the key of the per-IP throttles (docs/CONTRACTS.md §8).
//
// The default is the socket peer, which no client can forge. Only when
// trustProxy is on (COFFER_TRUST_PROXY=1, meaning the operator has put a reverse
// proxy in front) is X-Forwarded-For consulted, and then only the RIGHTMOST entry
// that is not itself a trusted proxy is taken.
//
// Rightmost matters: a client may send any X-Forwarded-For it likes, and a proxy
// appends to what it received, so the leftmost entry is whatever the attacker
// chose to write. The rightmost non-proxy entry is the one the nearest trusted hop
// observed. Taking the leftmost, or trusting the header unconditionally, would let
// one client mint unlimited "distinct" source addresses and walk past every per-IP
// limit.
//
// This is exported because the audit path and the login throttle must agree on one
// answer; a second resolver elsewhere would be a way for the two to disagree.
func SourceIP(r *http.Request, trustProxy bool) string {
	peer := socketPeer(r)
	if !trustProxy || r == nil {
		return peer
	}

	entries := forwardedFor(r)
	for i := len(entries) - 1; i >= 0; i-- {
		ip := normalizeIP(entries[i])
		if ip == "" {
			// A hop that is not an address tells us nothing; keep walking left.
			continue
		}
		if isTrustedProxy(ip) {
			continue
		}
		return ip
	}
	return peer
}

// forwardedFor flattens every X-Forwarded-For header, in order, into its entries.
func forwardedFor(r *http.Request) []string {
	values := r.Header.Values("X-Forwarded-For")
	entries := make([]string, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				entries = append(entries, trimmed)
			}
		}
	}
	return entries
}

// socketPeer returns the peer address of the connection, without its port.
func socketPeer(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return normalizeIP(host)
	}
	return normalizeIP(r.RemoteAddr)
}

// normalizeIP accepts a bare address, an address with a port, or a bracketed IPv6
// address, and returns the canonical address string, or "" when it is not an
// address. IPv4-mapped IPv6 addresses are unmapped so one client has one key.
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if zone := strings.IndexByte(raw, '%'); zone >= 0 {
		raw = raw[:zone]
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// isTrustedProxy reports whether addr belongs to the trusted-proxy set: loopback,
// link-local and private (RFC 1918 / RFC 4193) addresses.
//
// The set is derived rather than configured because the frozen environment list
// (docs/CONTRACTS.md §10) has no variable for it, and inventing one would be a
// contract change. It matches how Coffer is deployed: the proxy is the process on
// the loopback interface or the peer container on a private bridge.
//
// Consequence, recorded in the slice doc: with trustProxy on, a client that
// connects to the proxy from a private address is itself indistinguishable from a
// proxy hop, so its request is attributed to the nearest non-private hop to its
// left, or to the proxy when there is none. That over-attributes to the proxy and
// never under-attributes to an attacker, which is the safe direction for both the
// audit log and the throttle key.
func isTrustedProxy(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
