// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"net"
	"os/user"
	"path/filepath"
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

// TestContainMetricsDefaultIsCheckedBeforeItIsWritten covers the host where the
// inserted default is itself unsafe.
//
// The default metrics listener is a fixed port. On a host whose proxy already
// runs there, writing it unchecked has the installer produce a config its own
// runtime refuses, so metrics come up disabled and the stated reason points at
// a line the operator never wrote. Refusing during migration puts the problem
// in front of them while they can still choose a port.
func TestContainMetricsDefaultIsCheckedBeforeItIsWritten(t *testing.T) {
	_, defaultPort, err := net.SplitHostPort(containMetricsListen)
	if err != nil {
		t.Fatal(err)
	}

	migrate := func(t *testing.T, source string) ([]byte, error) {
		t.Helper()
		env, _, _ := newFakeEnv(t)
		home := t.TempDir()
		origLookup := env.lookupUser
		env.lookupUser = func(name string) (*user.User, error) {
			if name == containInstallOperatorUser {
				return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
			}
			return origLookup(name)
		}
		out, _, migrateErr := migratePipelockConfigForContain(env, filepath.Join(home, "pipelock.yaml"), []byte(source))
		return out, migrateErr
	}

	t.Run("refuses when the proxy occupies the default metrics port", func(t *testing.T) {
		out, err := migrate(t, "fetch_proxy:\n  listen: 127.0.0.1:"+defaultPort+"\n")
		if err == nil {
			t.Fatalf("migration wrote a config the runtime will refuse:\n%s", out)
		}
		if !strings.Contains(err.Error(), "collides") {
			t.Errorf("error = %q, want it to name the collision so the operator can pick a port", err.Error())
		}
	})

	t.Run("still inserts the default when there is no collision", func(t *testing.T) {
		out, err := migrate(t, "fetch_proxy:\n  listen: 127.0.0.1:8888\n")
		if err != nil {
			t.Fatalf("migration refused an ordinary host: %v", err)
		}
		if !strings.Contains(string(out), containMetricsListen) {
			t.Errorf("default metrics listener was not inserted:\n%s", out)
		}
	})
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
