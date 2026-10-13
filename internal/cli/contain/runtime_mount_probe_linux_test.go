// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"fmt"
	"os/user"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestVerifyRuntimeGuardUsesSelectedProfile(t *testing.T) {
	original := filesystemCanaryRoot
	filesystemCanaryRoot = func() bool { return true }
	t.Cleanup(func() { filesystemCanaryRoot = original })
	for _, mode := range []string{config.ContainmentFilesystemModeOff, config.ContainmentFilesystemModeEnforce} {
		for _, refuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/refuse=%v", mode, refuse), func(t *testing.T) {
				profile := filesystemProfile{Mode: mode}
				if mode == config.ContainmentFilesystemModeEnforce {
					profile.Properties = []string{protectHomeTmpfsProperty, "ProtectSystem=strict"}
				}
				ran := false
				env := &probeEnv{
					agentUserName: "pipelock-agent", agentHome: "/home/pipelock-agent", port: 8888, pipelockTarget: "/usr/local/bin/pipelock", filesystem: profile,
					lookupUser: func(string) (*user.User, error) {
						return &user.User{Uid: "987", Gid: "987", HomeDir: "/home/pipelock-agent"}, nil
					}, groupIDs: func(*user.User) ([]string, error) { return []string{"987"}, nil },
					runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
						ran = true
						if name != systemdRunPath || !slices.Contains(args, "--setenv="+runtimeProtectHomeSetting(profile.Properties)) || !strings.Contains(strings.Join(args, " "), "/usr/local/bin/pipelock contain assert-agent-netns --agent-user pipelock-agent --proxy-port 8888") {
							t.Fatalf("guard invocation: %s %v", name, args)
						}
						for _, p := range profile.Properties {
							if !slices.Contains(args, "--property="+p) {
								t.Fatalf("missing property %s", p)
							}
						}
						if refuse {
							return "unexpected runtime exposure: /run/probe", 2, nil
						}
						return "", 0, nil
					},
				}
				if mode == config.ContainmentFilesystemModeEnforce && !refuse {
					// Call the runtime portion directly: the separate existing filesystem
					// canary has its own filesystem operations and tests.
					status, detail := probeManagedRuntimeMounts(context.Background(), env, profile)
					if status != statusPass {
						t.Fatalf("%s %s", status, detail)
					}
				} else {
					status, detail := probeFilesystemConfinement(context.Background(), env)
					want := statusFilesystemOff
					if refuse {
						want = statusFail
					}
					if status != want || (refuse && !strings.Contains(detail, "managed launch runtime guard refused")) {
						t.Fatalf("%s %s", status, detail)
					}
				}
				if !ran {
					t.Fatal("verify did not exercise the launch guard")
				}
			})
		}
	}
}

func TestRuntimeProfileContextTransport(t *testing.T) {
	for _, properties := range [][]string{nil, {protectHomeTmpfsProperty}} {
		args := insertSystemdRuntimeSetting([]string{"--wait", "--", "/bin/true"}, properties)
		idx := slices.Index(args, "--setenv="+runtimeProtectHomeSetting(properties))
		if idx < 0 || idx > slices.Index(args, "--") {
			t.Fatalf("context not passed before command: %v", args)
		}
		t.Setenv(runtimeProtectHomeEnv, strings.TrimPrefix(runtimeProtectHomeSetting(properties), runtimeProtectHomeEnv+"="))
		if got := defaultNetnsAssertEnv().unitProperties; !slices.Equal(got, properties) {
			t.Fatalf("properties=%v want=%v", got, properties)
		}
	}
	for _, mode := range []string{config.ContainmentFilesystemModeOff, config.ContainmentFilesystemModeEnforce} {
		profile := filesystemProfile{Mode: mode}
		if mode == config.ContainmentFilesystemModeEnforce {
			profile.Properties = []string{protectHomeTmpfsProperty}
		}
		cmd, _ := containedAgentPrivateTmpCommand(containedAgentCommandOptions{ctx: context.Background(), filesystem: profile})
		if !slices.Contains(cmd.Args, "--setenv="+runtimeProtectHomeSetting(profile.Properties)) {
			t.Fatalf("launch missing context: %v", cmd.Args)
		}
	}
	wrapper := renderContainedLaunchWrapper(&installEnv{pipelockTarget: "/usr/local/bin/pipelock", agentUserName: "pipelock-agent", agentHome: "/home/pipelock-agent", proxyPort: 8888})
	if !strings.Contains(wrapper, "runtime_protect_home=''") || !strings.Contains(wrapper, "ProtectHome=tmpfs") || !strings.Contains(wrapper, "--setenv="+runtimeProtectHomeEnv+"=\"${runtime_protect_home}\"") {
		t.Fatalf("wrapper lacks explicit property context: %s", wrapper)
	}
}
