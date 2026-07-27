// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func TestFallbackCmd_ShowsReplayWatermarkAndHash(t *testing.T) {
	if testing.Short() {
		t.Skip("fallback test requires a pre-recorded run dir from a real live run")
	}

	var buf bytes.Buffer
	dir, orchKey := cmdTestRunDir(t)

	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"fallback", dir, "--orchestrator-key", orchKey})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("fallback must exit 0 on valid recorded dir, got: %v\noutput:\n%s", err, buf.String())
	}

	out := buf.String()

	// Must contain REPLAY watermark.
	if !strings.Contains(out, "REPLAY") {
		t.Fatalf("output must contain REPLAY watermark, got:\n%s", out)
	}

	// Must contain the packet hash.
	if !strings.Contains(out, "sha256:") {
		t.Fatalf("output must contain packet hash (sha256:), got:\n%s", out)
	}

	// Must contain the verify command.
	if !strings.Contains(out, "verify") {
		t.Fatalf("output must contain verify command, got:\n%s", out)
	}
}

func TestRunCmd_Uncontained_ExitZero(t *testing.T) {
	if testing.Short() {
		t.Skip("run test builds binaries and boots a real proxy")
	}

	rd := t.TempDir()
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--run-dir", rd, "--scenario", playground.LiveDemoScenarioID})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("run --uncontained must exit 0, got: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "VERIFY OK") {
		t.Fatalf("output must contain VERIFY OK, got:\n%s", out)
	}
}

func TestRunCmd_SelfManagedContainmentRequiresContained(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"run",
		"--run-dir", t.TempDir(),
		"--self-managed-containment",
		"--toyagent-bin", "/tmp/probe",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --contained") {
		t.Fatalf("error = %v, want --contained requirement", err)
	}
}

func TestRunCmd_ContainedRejectsImpossibleStockPortCollision(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"run", "--run-dir", t.TempDir(), "--contained"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "stock contain service") {
		t.Fatalf("error = %v, want stock proxy collision explanation", err)
	}
}

func TestRunCmd_SelfManagedContainmentRequiresProbeBinary(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"run",
		"--run-dir", t.TempDir(),
		"--contained",
		"--self-managed-containment",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "requires --toyagent-bin") {
		t.Fatalf("error = %v, want --toyagent-bin requirement", err)
	}
}

func TestRunCmd_SelfManagedContainmentRejectsExplicitZeroProxyPort(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"run",
		"--run-dir", t.TempDir(),
		"--contained",
		"--self-managed-containment",
		"--toyagent-bin", "/tmp/probe",
		"--proxy-port", "0",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "1-65535") {
		t.Fatalf("error = %v, want proxy-port range error", err)
	}
}

func TestRunCmd_SelfManagedContainmentRejectsNegativeUIDs(t *testing.T) {
	for _, flag := range []string{"--operator-uid", "--proxy-uid"} {
		t.Run(flag, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs([]string{
				"run", "--run-dir", t.TempDir(), "--contained", "--self-managed-containment",
				"--toyagent-bin", "/tmp/probe", flag, "-1",
			})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "must be non-negative") {
				t.Fatalf("error = %v, want uid range error", err)
			}
		})
	}
}

func TestRunCmd_UIDFlagsRequireSelfManagedContainment(t *testing.T) {
	for _, tc := range []struct {
		name, flag, value string
	}{
		{name: "operator uid", flag: "--operator-uid", value: "1000"},
		{name: "proxy uid", flag: "--proxy-uid", value: "967"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"run", "--run-dir", t.TempDir(), tc.flag, tc.value})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "require --self-managed-containment") {
				t.Fatalf("error = %v, want mode requirement", err)
			}
		})
	}
}

func TestRunCmd_ForwardsSelfManagedUIDFlags(t *testing.T) {
	original := newDemoContainmentHook
	t.Cleanup(func() { newDemoContainmentHook = original })
	t.Cleanup(func() { playground.SetContainmentHook(nil) })
	var gotOperator, gotProxy int
	newDemoContainmentHook = func(selfManaged bool, toyAgentBin string, operatorUID, proxyUID int) playground.ContainmentHook {
		if !selfManaged || toyAgentBin != "/nonexistent/toyagent" {
			t.Fatalf("factory args: selfManaged=%v toyAgentBin=%q", selfManaged, toyAgentBin)
		}
		gotOperator, gotProxy = operatorUID, proxyUID
		return demoContainmentHook(selfManaged, toyAgentBin, operatorUID, proxyUID)
	}

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"run", "--run-dir", t.TempDir(), "--contained", "--self-managed-containment",
		"--toyagent-bin", "/nonexistent/toyagent", "--operator-uid", "1000", "--proxy-uid", "967",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unproven containment should fail closed")
	}
	if gotOperator != 1000 || gotProxy != 967 {
		t.Fatalf("factory received operator=%d proxy=%d", gotOperator, gotProxy)
	}
}

func TestRunCmd_SelfManagedContainmentSelectsHookBeforeFailingProbe(t *testing.T) {
	playground.SetContainmentHook(nil)
	t.Cleanup(func() { playground.SetContainmentHook(nil) })
	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"run", "--run-dir", t.TempDir(), "--contained", "--self-managed-containment",
		"--toyagent-bin", "/nonexistent/toyagent", "--proxy-port", "8888",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unproven self-managed containment should fail closed")
	}
}

func TestDemoProxyPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contained     bool
		selfManaged   bool
		configured    int
		explicitlySet bool
		want          int
	}{
		{name: "uncontained stays ephemeral", configured: 8899, explicitlySet: true, want: 0},
		{name: "stock contained preserves existing behavior", contained: true, want: 0},
		{name: "self-managed defaults to managed port", contained: true, selfManaged: true, want: playground.DefaultContainedProxyPort},
		{name: "self-managed custom policy", contained: true, selfManaged: true, configured: 8899, explicitlySet: true, want: 8899},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := demoProxyPort(tc.contained, tc.selfManaged, tc.configured, tc.explicitlySet); got != tc.want {
				t.Fatalf("demoProxyPort() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestDemoContainmentHookSelection(t *testing.T) {
	t.Parallel()
	const probe = "/usr/local/bin/probe"
	self, ok := demoContainmentHook(true, probe, 1000, 967).(*playground.InVMContainmentHook)
	if !ok || self.ToyAgentBin != probe || self.OperatorUID != 1000 || self.ProxyUID != 967 {
		t.Fatalf("self-managed hook = %#v", self)
	}
	if _, ok := demoContainmentHook(false, probe, 1000, 967).(*playground.RealContainmentHook); !ok {
		t.Fatal("stock mode did not select RealContainmentHook")
	}
}
