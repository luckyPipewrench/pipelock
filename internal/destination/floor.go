// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import "net"

// metadataIPv4s lists the well-known cloud-provider instance-metadata IPv4
// endpoints. These are operationally distinct from generic private ranges: they
// serve short-lived credentials to anything that can reach them, so a hit gets
// its own block reason rather than the generic private-IP one.
var metadataIPv4s = map[string]struct{}{
	"169.254.169.254": {}, // AWS / Azure / GCP IMDS
	"168.63.129.16":   {}, // Azure WireServer
	"100.100.100.200": {}, // Alibaba Cloud ECS metadata
}

// metadataIPv6 lists the canonical IPv6 instance-metadata endpoints.
var metadataIPv6 = map[string]struct{}{
	"fd00:ec2::254": {}, // AWS IMDSv6
}

// IsCloudMetadataIP reports whether an address is a cloud instance-metadata
// endpoint. Callers use this to upgrade a generic SSRF block into the more
// specific metadata classification.
func IsCloudMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		_, ok := metadataIPv4s[v4.String()]
		return ok
	}
	_, ok := metadataIPv6[ip.String()]
	return ok
}

// IsNonOverridableSSRFTarget reports whether an address belongs to a class no
// configured allowlist may ever exempt: cloud instance-metadata endpoints,
// link-local ranges (which contain the IPv4 metadata address), multicast, and
// the unspecified address.
//
// Loopback and ordinary private ranges are deliberately NOT in this set —
// exempting a specific internal service address is the allowlist's intended
// use. This is the runtime floor that pairs with the config-load rejection, so
// a metadata endpoint cannot be allowlisted into reach by any path.
func IsNonOverridableSSRFTarget(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip = NormalizeIP(ip)
	return IsCloudMetadataIP(ip) ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}
