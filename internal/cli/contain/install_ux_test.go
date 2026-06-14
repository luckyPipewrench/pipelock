// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Item 3: sudo secure_path check
// ---------------------------------------------------------------------------

func TestCheckSudoSecurePath_IncludesLocalBin(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("sudo", "-V"),
		"Sudo version 1.9.5p2\n"+
			"Configure options: ...\n"+
			"Value to override user supplied: secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin\n",
		0, nil)

	warning := checkSudoSecurePath(env)
	if warning != "" {
		t.Fatalf("expected no warning when /usr/local/bin is in secure_path, got: %s", warning)
	}
}

func TestCheckSudoSecurePath_MissingLocalBin(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("sudo", "-V"),
		"Value to override user supplied: secure_path = /sbin:/bin:/usr/sbin:/usr/bin\n",
		0, nil)

	warning := checkSudoSecurePath(env)
	if warning == "" {
		t.Fatal("expected warning when /usr/local/bin is missing from secure_path")
	}
	if !strings.Contains(warning, "/usr/local/bin") {
		t.Errorf("warning should mention /usr/local/bin: %s", warning)
	}
	if !strings.Contains(warning, "sudoers") {
		t.Errorf("warning should mention sudoers: %s", warning)
	}
}

func TestCheckSudoSecurePath_SudoFails(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("sudo", "-V"), "", 1, nil)

	warning := checkSudoSecurePath(env)
	if warning != "" {
		t.Fatalf("expected empty warning when sudo -V fails, got: %s", warning)
	}
}

func TestCheckSudoSecurePath_NoSecurePathLine(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("sudo", "-V"),
		"Sudo version 1.9.5p2\nConfigure options: ...\n", 0, nil)

	warning := checkSudoSecurePath(env)
	if warning != "" {
		t.Fatalf("expected empty warning when no secure_path in output, got: %s", warning)
	}
}

func TestContainsPathEntry(t *testing.T) {
	tests := []struct {
		name     string
		pathList string
		entry    string
		want     bool
	}{
		{"present at start", "/usr/local/bin:/usr/bin:/bin", "/usr/local/bin", true},
		{"present at end", "/usr/bin:/bin:/usr/local/bin", "/usr/local/bin", true},
		{"present in middle", "/usr/bin:/usr/local/bin:/bin", "/usr/local/bin", true},
		{"absent", "/usr/bin:/bin:/sbin", "/usr/local/bin", false},
		{"empty path", "", "/usr/local/bin", false},
		{"single entry match", "/usr/local/bin", "/usr/local/bin", true},
		{"prefix mismatch", "/usr/local/bin2:/usr/bin", "/usr/local/bin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsPathEntry(tt.pathList, tt.entry)
			if got != tt.want {
				t.Errorf("containsPathEntry(%q, %q) = %v, want %v", tt.pathList, tt.entry, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Item 4: post-install next-actions
// ---------------------------------------------------------------------------

func TestPrintPostInstallNextActions_ContainsAgentRegistration(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.out = &bytes.Buffer{}

	// Mock sudo -V to return a clean secure_path.
	runner := newFakeRunner()
	runner.on(argvFor("sudo", "-V"),
		"Value to override user supplied: secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin\n",
		0, nil)
	env.runCmd = runner.run

	printPostInstallNextActions(env)
	output := env.out.(*bytes.Buffer).String()

	if !strings.Contains(output, "Next steps:") {
		t.Error("missing 'Next steps:' header")
	}
	if !strings.Contains(output, "add-tool") {
		t.Error("missing add-tool guidance")
	}
	if !strings.Contains(output, "plk-") {
		t.Error("missing plk- wrapper guidance")
	}
	if !strings.Contains(output, "receipts") {
		t.Error("missing receipts path")
	}
	if !strings.Contains(output, "logs") {
		t.Error("missing logs path")
	}
}

func TestPrintPostInstallNextActions_IncludesSecurePathWarning(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.out = &bytes.Buffer{}

	runner := newFakeRunner()
	runner.on(argvFor("sudo", "-V"),
		"Value to override user supplied: secure_path = /sbin:/bin:/usr/sbin:/usr/bin\n",
		0, nil)
	env.runCmd = runner.run

	printPostInstallNextActions(env)
	output := env.out.(*bytes.Buffer).String()

	if !strings.Contains(output, "WARNING") {
		t.Error("missing secure_path WARNING")
	}
	if !strings.Contains(output, "/usr/local/bin") {
		t.Error("warning should mention /usr/local/bin")
	}
}

// ---------------------------------------------------------------------------
// Item 5: evidence paths in doctor output
// ---------------------------------------------------------------------------

func TestPrintEvidencePaths(t *testing.T) {
	var buf bytes.Buffer
	printEvidencePaths(&buf)
	output := buf.String()

	if !strings.Contains(output, "Evidence paths:") {
		t.Error("missing 'Evidence paths:' header")
	}
	if !strings.Contains(output, "/var/lib/pipelock/logs") {
		t.Errorf("missing logs path, got: %s", output)
	}
	if !strings.Contains(output, "/var/lib/pipelock/recorder") {
		t.Errorf("missing receipts path, got: %s", output)
	}
}

// ---------------------------------------------------------------------------
// Item 6: nft version parsing and checking
// ---------------------------------------------------------------------------

func TestParseNFTVersion(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{
			name:      "standard format",
			output:    "nftables v0.9.3 (Topsy)",
			wantMajor: 0, wantMinor: 9, wantOK: true,
		},
		{
			name:      "v1 format",
			output:    "nftables v1.0.6 (Lester Gooch #5)",
			wantMajor: 1, wantMinor: 0, wantOK: true,
		},
		{
			name:      "old format",
			output:    "nftables v0.4 (Dingbat)",
			wantMajor: 0, wantMinor: 4, wantOK: true,
		},
		{
			name:      "newline terminated",
			output:    "nftables v0.9.0\n",
			wantMajor: 0, wantMinor: 9, wantOK: true,
		},
		{
			name:   "no version",
			output: "something else entirely",
			wantOK: false,
		},
		{
			name:   "empty output",
			output: "",
			wantOK: false,
		},
		{
			name:   "just v",
			output: "v",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, ok := parseNFTVersion(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("parseNFTVersion(%q) ok=%v, want %v", tt.output, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Fatalf("parseNFTVersion(%q) = (%d, %d), want (%d, %d)",
					tt.output, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestCheckNFTVersion_Sufficient(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "nftables v0.9.3 (Topsy)", 0, nil)

	err := checkNFTVersion(context.Background(), env)
	if err != nil {
		t.Fatalf("expected nil error for sufficient version, got: %v", err)
	}
}

func TestCheckNFTVersion_TooOld(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "nftables v0.4 (Dingbat)", 0, nil)

	err := checkNFTVersion(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for version too old")
	}
	if !strings.Contains(err.Error(), "too old") {
		t.Errorf("error should mention 'too old': %v", err)
	}
	if !strings.Contains(err.Error(), "0.6") {
		t.Errorf("error should mention minimum version 0.6: %v", err)
	}
	if !strings.Contains(err.Error(), "Upgrade nftables") {
		t.Errorf("error should include upgrade guidance: %v", err)
	}
}

func TestCheckNFTVersion_V1Passes(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "nftables v1.0.6 (Lester Gooch #5)", 0, nil)

	err := checkNFTVersion(context.Background(), env)
	if err != nil {
		t.Fatalf("expected nil error for v1.0.6, got: %v", err)
	}
}

func TestCheckNFTVersion_ExactMinimum(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "nftables v0.6.0 (Flux)", 0, nil)

	err := checkNFTVersion(context.Background(), env)
	if err != nil {
		t.Fatalf("expected nil error at exact minimum version 0.6, got: %v", err)
	}
}

func TestCheckNFTVersion_UnparseablePassesThrough(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "something unexpected", 0, nil)

	err := checkNFTVersion(context.Background(), env)
	if err != nil {
		t.Fatalf("expected nil error for unparseable version (fail-open to nft -c -f), got: %v", err)
	}
}

func TestCheckNFTVersion_NftCmdFails(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("nft", "-v"), "", 1, nil)

	err := checkNFTVersion(context.Background(), env)
	if err != nil {
		t.Fatalf("expected nil error when nft -v fails (preflight passed), got: %v", err)
	}
}
