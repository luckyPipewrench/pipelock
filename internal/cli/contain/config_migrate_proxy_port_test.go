// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"strings"
	"testing"
)

// TestContainServiceReadOnlyPathsUsesTheConfiguredProxyPort covers a host that
// does not run the proxy on the installer's default port.
//
// The metrics listener must differ from the port the contained agent can reach.
// Every caller here passed the installer's port, which is the default on almost
// every host, so a host with its own fetch_proxy.listen was checked against a
// port nothing was listening on. That is permissive in the direction that
// matters: a metrics_listen equal to the REAL proxy port passed these checks and
// was then refused by the runtime, so the upgrade and the probe both reported a
// host safe that the service itself would not accept.
func TestContainServiceReadOnlyPathsUsesTheConfiguredProxyPort(t *testing.T) {
	const installerPort = 8888

	tests := []struct {
		name       string
		config     string
		wantReject bool
		because    string
	}{
		{
			name:       "metrics on the configured proxy port is rejected",
			config:     "fetch_proxy:\n  listen: 127.0.0.1:9999\nmetrics_listen: 127.0.0.1:9999\n",
			wantReject: true,
			because:    "the metrics listener is the port the agent reaches",
		},
		{
			name:       "metrics on the installer default is fine when the proxy moved",
			config:     "fetch_proxy:\n  listen: 127.0.0.1:9999\nmetrics_listen: 127.0.0.1:8888\n",
			wantReject: false,
			because:    "nothing the agent can reach is on 8888 here",
		},
		{
			name:       "metrics on the installer default is rejected when the proxy is there",
			config:     "fetch_proxy:\n  listen: 127.0.0.1:8888\nmetrics_listen: 127.0.0.1:8888\n",
			wantReject: true,
			because:    "the configured port agrees with the fallback",
		},
		{
			name:       "no fetch_proxy.listen falls back to the installer port",
			config:     "metrics_listen: 127.0.0.1:8888\n",
			wantReject: true,
			because:    "an omitted listener really does run on the installer's port",
		},
		{
			name:       "an unparsable listener falls back rather than passing everything",
			config:     "fetch_proxy:\n  listen: \"not-a-host-port\"\nmetrics_listen: 127.0.0.1:8888\n",
			wantReject: true,
			because:    "a malformed listener must not silently disable the comparison",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := containServiceReadOnlyPaths([]byte(tt.config), installerPort)
			rejected := err != nil
			if rejected != tt.wantReject {
				t.Fatalf("rejected = %v, want %v (%s); err = %v", rejected, tt.wantReject, tt.because, err)
			}
			if tt.wantReject && !strings.Contains(err.Error(), "unsafe for containment") {
				t.Errorf("error = %q, want it to name the containment refusal", err.Error())
			}
		})
	}
}

// TestEffectiveProxyPortFallsBackRatherThanGuessing covers each way the
// configured listener can fail to yield a port.
//
// Every one of these has to fall back to the installer's port. Treating an
// unreadable listener as "no comparison needed" would let a metrics listener on
// the agent-reachable port through, which is the direction that costs something.
func TestEffectiveProxyPortFallsBackRatherThanGuessing(t *testing.T) {
	const fallback = 8888

	tests := []struct {
		name   string
		config string
		want   int
	}{
		{"no fetch_proxy block", "mode: balanced\n", fallback},
		{"fetch_proxy with no listen", "fetch_proxy:\n  enabled: true\n", fallback},
		{"listen is blank", "fetch_proxy:\n  listen: \"\"\n", fallback},
		{"listen has no port separator", "fetch_proxy:\n  listen: \"127.0.0.1\"\n", fallback},
		{"port is not a number", "fetch_proxy:\n  listen: \"127.0.0.1:http\"\n", fallback},
		{"port is zero", "fetch_proxy:\n  listen: \"127.0.0.1:0\"\n", fallback},
		{"port is above the range", "fetch_proxy:\n  listen: \"127.0.0.1:70000\"\n", fallback},
		{"a usable port wins", "fetch_proxy:\n  listen: \"127.0.0.1:9999\"\n", 9999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := parseSingleYAMLDocument([]byte(tt.config))
			if err != nil {
				t.Fatal(err)
			}
			if got := effectiveProxyPort(documentMapping(root), fallback); got != tt.want {
				t.Errorf("effectiveProxyPort = %d, want %d", got, tt.want)
			}
		})
	}
}
