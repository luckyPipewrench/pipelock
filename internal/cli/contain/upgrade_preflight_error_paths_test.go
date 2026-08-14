// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestPreflightUpgradeManagedConfigRefusals covers the refusal branches of the
// upgrade preflight.
//
// Every branch here is a reason to stop BEFORE the binary is replaced or the
// service restarted. They matter more than the happy path: this preflight exists
// because `contain upgrade` previously performed the whole upgrade and then called
// a verify that could not see the drift, so a drifted host was upgraded and
// reported successful.
func TestPreflightUpgradeManagedConfigRefusals(t *testing.T) {
	const safeConfig = "metrics_listen: 127.0.0.1:9091\n"

	tests := []struct {
		name    string
		arrange func(t *testing.T, env *upgradeEnv)
		wantErr string
	}{
		{
			name: "unreadable managed config",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				env.readFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
			},
			wantErr: "read managed config",
		},
		{
			name: "config violates the containment contract",
			arrange: func(t *testing.T, env *upgradeEnv) {
				if err := writeFileAtomic(env.configPath, []byte("metrics_listen: 10.20.0.20:9091\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "validate managed config",
		},
		{
			name: "deployed binary cannot be hashed before the check",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				env.hashFile = func(string) (string, error) { return "", errors.New("no such file") }
			},
			wantErr: "hash deployed binary before config check",
		},
		{
			name: "the deployed binary fails to run",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return "", 0, errors.New("exec format error")
				}
			},
			wantErr: "run deployed binary config check",
		},
		{
			name: "the deployed binary rejects the config",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return "Config validation FAILED: something is wrong", 1, nil
				}
			},
			wantErr: "deployed binary rejected managed config",
		},
		{
			name: "the deployed binary rejects the config without saying why",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return "   ", 3, nil
				}
			},
			wantErr: "exited 3",
		},
		{
			name: "the binary changes underneath the check",
			arrange: func(_ *testing.T, env *upgradeEnv) {
				calls := 0
				env.hashFile = func(string) (string, error) {
					calls++
					if calls == 1 {
						return "hash-before", nil
					}
					return "hash-after", nil
				}
			},
			wantErr: "deployed binary changed during managed config check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := testUpgradeEnv(t)
			if err := writeFileAtomic(env.configPath, []byte(safeConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			if env.runCmd == nil {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
			}
			tt.arrange(t, env)

			err := preflightUpgradeManagedConfig(context.Background(), env)
			if err == nil {
				t.Fatalf("preflight accepted a state it must refuse (%s)", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestPreflightUpgradeManagedConfigAcceptsACompliantHost is the positive control.
// Without it the refusals above could all pass on a preflight that refuses
// everything, which would block every upgrade rather than only drifted ones.
func TestPreflightUpgradeManagedConfigAcceptsACompliantHost(t *testing.T) {
	env := testUpgradeEnv(t)
	if err := writeFileAtomic(env.configPath, []byte("metrics_listen: 127.0.0.1:9091\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "Config validation: OK", 0, nil
	}
	if err := preflightUpgradeManagedConfig(context.Background(), env); err != nil {
		t.Fatalf("preflight refused a compliant host: %v", err)
	}
}
