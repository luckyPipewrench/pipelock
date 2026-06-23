// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const cfConnectingIPHeader = "CF-Connecting-IP"

// cloudflareProxyPrefixes is a snapshot of Cloudflare's published proxy IP
// ranges used to validate CF-Connecting-IP headers. These are NOT fetched at
// runtime (avoids a network dependency at startup).
//
// Sources:
//   - IPv4: https://www.cloudflare.com/ips-v4
//   - IPv6: https://www.cloudflare.com/ips-v6
//
// Last refreshed: 2026-06-23
// Refresh via scripts/check-cloudflare-ranges.sh.
var cloudflareProxyPrefixes = []netip.Prefix{
	mustParsePrefix("173.245.48.0/20"),
	mustParsePrefix("103.21.244.0/22"),
	mustParsePrefix("103.22.200.0/22"),
	mustParsePrefix("103.31.4.0/22"),
	mustParsePrefix("141.101.64.0/18"),
	mustParsePrefix("108.162.192.0/18"),
	mustParsePrefix("190.93.240.0/20"),
	mustParsePrefix("188.114.96.0/20"),
	mustParsePrefix("197.234.240.0/22"),
	mustParsePrefix("198.41.128.0/17"),
	mustParsePrefix("162.158.0.0/15"),
	mustParsePrefix("104.16.0.0/13"),
	mustParsePrefix("104.24.0.0/14"),
	mustParsePrefix("172.64.0.0/13"),
	mustParsePrefix("131.0.72.0/22"),
	mustParsePrefix("2400:cb00::/32"),
	mustParsePrefix("2606:4700::/32"),
	mustParsePrefix("2803:f800::/32"),
	mustParsePrefix("2405:b500::/32"),
	mustParsePrefix("2405:8100::/32"),
	mustParsePrefix("2a06:98c0::/29"),
	mustParsePrefix("2c0f:f248::/32"),
}

// ClientIP returns the abuse-budget identity for an HTTP request.
//
// CF-Connecting-IP is accepted only when the direct peer is in Cloudflare's
// published proxy ranges. That keeps the public broker usable behind Cloudflare
// while failing closed against direct clients that forge Cloudflare headers.
//
// IPv6 sources are collapsed to their /64 network so a single allocation cannot
// mint unlimited per-IP rate/budget buckets by rotating addresses. Use
// [ClientIPExact] where the precise source address matters (e.g. the Turnstile
// Siteverify remoteip), never for rate-limit or budget keys.
func ClientIP(r *http.Request, trustForwardedFor bool) string {
	return abuseBucket(ClientIPExact(r, trustForwardedFor))
}

// ClientIPExact resolves the client IP without abuse-bucket normalization. It
// applies the same Cloudflare/forwarded-for trust rules as [ClientIP] but
// returns the full address.
func ClientIPExact(r *http.Request, trustForwardedFor bool) string {
	if r == nil {
		return ""
	}
	peer := remoteHost(r.RemoteAddr)
	if ip := cloudflareConnectingIP(r, peer); ip != "" {
		return ip
	}
	if trustForwardedFor {
		if ip := firstForwardedFor(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	return peer
}

// abuseBucket collapses an IPv6 address to its /64 network so rotating within a
// single allocation does not bypass per-IP rate limits or budgets. IPv4 and
// IPv4-mapped IPv6 addresses (and anything that does not parse as an IP) are
// returned unchanged.
func abuseBucket(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.Masked().String()
}

func cloudflareConnectingIP(r *http.Request, peer string) string {
	if !isCloudflareProxy(peer) {
		return ""
	}
	raw := strings.TrimSpace(r.Header.Get(cfConnectingIPHeader))
	if raw == "" {
		return ""
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	return addr.String()
}

func isCloudflareProxy(raw string) bool {
	addr, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return false
	}
	for _, p := range cloudflareProxyPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func firstForwardedFor(raw string) string {
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, ','); i >= 0 {
		raw = raw[:i]
	}
	segment := strings.TrimSpace(raw)
	if segment == "" {
		return ""
	}
	// Validate the segment is a real IP address; return empty on parse
	// failure so the caller falls back to the peer address rather than using
	// a garbage string as a rate-limit/budget key or Turnstile remoteip.
	addr, err := netip.ParseAddr(segment)
	if err != nil {
		return ""
	}
	return addr.String()
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func mustParsePrefix(raw string) netip.Prefix {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		panic(err)
	}
	return prefix
}
