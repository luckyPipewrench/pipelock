// dnsresolver.go — host-level DNS resolver used by SSRF checks and the
// proxy dial path. The default resolver is net.DefaultResolver. Operators
// may configure dns.host_overrides to map specific hostnames to static IPs
// without touching system /etc/hosts; this is used by reproducible test
// harnesses (e.g. agent-egress-bench) so a benchmark fixture published on
// loopback can be reached at a trusted hostname while raw-IP SSRF attacks
// targeting the same range still get rejected.
//
// Semantics:
//   - Lookup matches on the hostname only (lowercased, trailing dot stripped).
//     IP literals never hit overrides — the IP path bypasses the resolver.
//   - If a hostname is in the override map, the static IPs are returned and
//     the upstream resolver is not consulted. A trusted_domains entry for
//     the same hostname tells the SSRF check to permit those IPs even when
//     they fall inside RFC1918 / loopback.
//   - If a hostname is NOT in the override map, the upstream resolver runs
//     normally — fail-closed behavior on DNS errors is preserved.

package scanner

import (
	"context"
	"net"
	"strings"
)

// Resolver abstracts DNS hostname lookups so the scanner and proxy can be
// driven by an override-aware implementation in tests and reproducible
// benchmarks. The shape matches the subset of *net.Resolver that the
// proxy and SSRF check actually consume.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// StaticOverrideResolver answers static hostname-to-IP mappings before
// delegating to an upstream resolver. The override map is built once at
// construction and is safe for concurrent reads; constructors normalize
// hostname keys to lowercase and strip a trailing dot.
type StaticOverrideResolver struct {
	overrides map[string][]string
	upstream  Resolver
}

// NewStaticOverrideResolver builds a resolver that returns the configured
// IPs for any matching hostname and delegates everything else to upstream.
// If upstream is nil, net.DefaultResolver is used.
func NewStaticOverrideResolver(overrides map[string][]string, upstream Resolver) *StaticOverrideResolver {
	if upstream == nil {
		upstream = net.DefaultResolver
	}
	norm := make(map[string][]string, len(overrides))
	for host, ips := range overrides {
		key := normalizeHostKey(host)
		if key == "" {
			continue
		}
		if net.ParseIP(key) != nil {
			continue
		}
		// Defensive copy so caller mutations after construction do not
		// leak into the resolver's state.
		cp := make([]string, len(ips))
		copy(cp, ips)
		norm[key] = cp
	}
	return &StaticOverrideResolver{overrides: norm, upstream: upstream}
}

// LookupHost returns the override IPs for known hostnames, falling back to
// the upstream resolver. IP literals are passed straight through to the
// upstream so net.ParseIP-style fast paths remain unchanged.
func (r *StaticOverrideResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	key := normalizeHostKey(host)
	if net.ParseIP(key) != nil {
		return r.upstream.LookupHost(ctx, host)
	}
	if ips, ok := r.overrides[key]; ok {
		out := make([]string, len(ips))
		copy(out, ips)
		return out, nil
	}
	return r.upstream.LookupHost(ctx, host)
}

func normalizeHostKey(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	return strings.ToLower(host)
}
