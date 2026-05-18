// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import "testing"

func TestNetworkPolicyHasPortExact(t *testing.T) {
	t.Parallel()

	policy := `
spec:
  egress:
    - ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 4430
        - protocol: TCP
          port: 88890
        - protocol: TCP
          port: 30000
        - protocol: TCP
          port: 8889 # mcp
`

	for _, port := range []int{80, 443, 8888, 3000} {
		if networkPolicyHasPort(policy, port) {
			t.Fatalf("networkPolicyHasPort matched substring port %d", port)
		}
	}
	if !networkPolicyHasPort(policy, 8889) {
		t.Fatal("networkPolicyHasPort should match exact port line")
	}
}
