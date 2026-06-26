// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

// ProbeResult holds the outcome of a single direct-egress probe. It is
// serialized into the signed HostContainmentWitness, so its JSON shape is part
// of the evidence model: the field tags must stay stable for SignedBytes
// determinism.
type ProbeResult struct {
	// Target is the host:port that was probed.
	Target string `json:"target"`
	// Open is true when the probe connected successfully (egress is NOT blocked).
	Open bool `json:"open"`
	// Blocked is true only when the probe failed in a way consistent with a
	// kernel/network egress denial. Reachable-but-closed targets (connection
	// refused) are NOT blocked: they prove packets escaped far enough to get a
	// response.
	Blocked bool `json:"blocked"`
	// Detail is a human-readable classification (e.g. "connected", "connection refused").
	Detail string `json:"detail"`
}

// DirectEgressTargets returns the exact direct-egress target suite a contained
// witness must cover.
func DirectEgressTargets() []string {
	return []string{
		"169.254.169.254:80", // cloud metadata
		"10.0.0.1:443",       // RFC-1918 private
		"8.8.8.8:53",         // public DNS (Google)
		"1.1.1.1:853",        // public DNS over TLS (Cloudflare)
		"93.184.216.34:443",  // public HTTPS (example.com)
	}
}

// LocalEscapeTargets returns local, non-network surfaces the contained agent
// must not be able to use.
func LocalEscapeTargets() []string {
	return []string{
		"unix:/.fly/api",            // Fly.io local control socket
		"unix:/var/run/docker.sock", // classic container escape control socket
		"device:/dev/vda",           // common Fly/KVM block device
		"device:/dev/vdb",           // common Fly/KVM data block device
		"device:/dev/root",          // root block-device alias
		"device:/dev/nvme0n1",       // common NVMe block device
		"device:/dev/sda",           // common virt/SCSI block device
		"device:/dev/fuse",          // unmediated FUSE mount surface
		"cap:mknod",                 // create new device nodes
		"cap:mount",                 // mount a filesystem
		"cap:userns-mount",          // create user namespace root and mount
	}
}
