// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want [3]int
	}{
		{"v2.7.0", true, [3]int{2, 7, 0}},
		{"2.7.0-rc1", true, [3]int{2, 7, 0}},
		{"2.7.0+build", true, [3]int{2, 7, 0}},
		{"unknown", false, [3]int{}},
		{"2.7", false, [3]int{}},
		{"a.b.c", false, [3]int{}},
		{"2.x.0", false, [3]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			maj, minor, patch, ok := parseSemver(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (maj != tc.want[0] || minor != tc.want[1] || patch != tc.want[2]) {
				t.Fatalf("got %d.%d.%d want %v", maj, minor, patch, tc.want)
			}
		})
	}
}

func TestCheck_FetchError(t *testing.T) {
	opts := &Options{
		APIBase:        "http://127.0.0.1:0", // unroutable
		TargetPath:     writeTargetBinary(t, "x"),
		CurrentVersion: testCurrent,
	}
	if _, err := opts.Check(context.Background()); err == nil {
		t.Fatal("expected fetch error")
	}
}

func TestRun_UpToDate(t *testing.T) {
	// Latest equals current and no pin -> ErrUpToDate, no changes.
	assets, _ := standardAssets(t, testCurrent, testGOOS)
	rs := newReleaseServer(t, testCurrent, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	_, err := opts.Run(context.Background())
	if !errors.Is(err, ErrUpToDate) {
		t.Fatalf("expected ErrUpToDate, got %v", err)
	}
	if string(readT(target)) != "ORIGINAL" {
		t.Fatalf("target mutated: %q", readT(target))
	}
}

func TestExtractBinary_SkipsNonMatchingEntries(t *testing.T) {
	dir := t.TempDir()
	// tar.gz with a README and a dir-like prefixed entry before the real binary.
	archive := makeTarGz(t, map[string][]byte{
		"README.md":  []byte("docs"),
		"sub/notbin": []byte("noise"),
		binaryName:   fakeBinaryBytes("2.8.0"),
	})
	tmp, err := extractBinary(archive, false, dir, binaryName)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, _ := os.ReadFile(tmp) // #nosec G304 -- test temp file
	if !strings.Contains(string(got), "version 2.8.0") {
		t.Fatalf("wrong binary extracted: %q", got)
	}
}

func TestExtractZip_SkipsNonMatchingAndDirs(t *testing.T) {
	dir := t.TempDir()
	archive := makeZip(t, map[string][]byte{
		"README.md": []byte("docs"),
		binaryName:  fakeBinaryBytes("2.8.0"),
	})
	tmp, err := extractBinary(archive, true, dir, binaryName)
	if err != nil {
		t.Fatalf("extract zip: %v", err)
	}
	got, _ := os.ReadFile(tmp) // #nosec G304 -- test temp file
	if !strings.Contains(string(got), "version 2.8.0") {
		t.Fatalf("wrong binary extracted from zip: %q", got)
	}
}

func TestExtractBinary_NotFound(t *testing.T) {
	dir := t.TempDir()
	// Archive with a different binary name only.
	archive := makeTarGz(t, map[string][]byte{"other-tool": []byte("x")})
	_, err := extractBinary(archive, false, dir, binaryName)
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("expected ErrAssetNotFound, got %v", err)
	}
}

func TestExtractBinary_BadGzip(t *testing.T) {
	dir := t.TempDir()
	_, err := extractBinary([]byte("not gzip"), false, dir, binaryName)
	if err == nil {
		t.Fatal("expected gzip error")
	}
}

func TestExtractBinary_BadZip(t *testing.T) {
	dir := t.TempDir()
	_, err := extractBinary([]byte("not a zip"), true, dir, binaryName)
	if err == nil {
		t.Fatal("expected zip error")
	}
}

func TestRollback_StatError(t *testing.T) {
	// backup path is a directory's child where the parent is a file -> stat
	// returns a non-NotExist error path is hard to force portably; instead point
	// target into a missing nested dir so backup stat returns NotExist -> ErrNoBackup.
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "pipelock")
	opts := &Options{TargetPath: target, CurrentVersion: testCurrent, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	_, err := opts.Rollback(context.Background())
	// checkWritable fails first (dir doesn't exist) OR ErrNoBackup; both are non-nil aborts.
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmd_RunE_CheckEndToEnd(t *testing.T) {
	// Drive the actual cobra RunE with --check without allowing a live network
	// dial. A canceled context exercises the command path and must fail closed.
	cmd := Cmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--check", "--json"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected canceled context error")
	}
	// Clean fail-closed error path, never a panic.
	if strings.Contains(out.String(), "panic") {
		t.Fatalf("unexpected panic output: %q", out.String())
	}
}

func TestLacksUpdateCommand(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"v2.7.0", true},
		{"v2.7.5", true},
		{"v2.6.0", true},
		{"v1.0.0", true},
		{"v2.8.0", false},
		{"v2.8.1", false},
		{"v3.0.0", false},
		{"v2.8.0-rc1", false}, // pre-release of v2.8.0 still parses as 2.8.0
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got := lacksUpdateCommand(tc.version)
			if got != tc.want {
				t.Fatalf("lacksUpdateCommand(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestRun_DowngradeWarnsAboutMissingRollback(t *testing.T) {
	const downgradeTarget = "v2.7.0"
	assets, _ := standardAssets(t, downgradeTarget, testGOOS)
	rs := newReleaseServer(t, downgradeTarget, assets)
	target := writeTargetBinary(t, "CURRENT")

	stderr := &bytes.Buffer{}
	opts := baseOptions(rs, target)
	opts.CurrentVersion = "v2.8.0"
	opts.TargetVersion = downgradeTarget
	opts.Stderr = stderr

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !st.Applied {
		t.Fatal("expected update to be applied")
	}

	// Must warn about missing rollback command.
	warn := stderr.String()
	if !strings.Contains(warn, "predates the 'update' command") {
		t.Fatalf("expected downgrade warning, got stderr: %q", warn)
	}
	if !strings.Contains(warn, "mv") {
		t.Fatalf("expected manual recovery command in warning, got: %q", warn)
	}
	if !strings.Contains(warn, st.BackupPath) {
		t.Fatalf("expected backup path in warning, got: %q", warn)
	}
}

func TestRun_UpgradeDoesNotWarnAboutRollback(t *testing.T) {
	// Upgrading to v2.8.0+ should NOT emit the downgrade warning.
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")

	stderr := &bytes.Buffer{}
	opts := baseOptions(rs, target)
	opts.Stderr = stderr

	st, err := opts.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !st.Applied {
		t.Fatal("expected update to be applied")
	}
	if strings.Contains(stderr.String(), "predates") {
		t.Fatalf("unexpected downgrade warning on upgrade: %q", stderr.String())
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/usr/local/bin/pipelock", `'/usr/local/bin/pipelock'`},
		{"/path with spaces/pipelock", `'/path with spaces/pipelock'`},
		{"/odd/$(rm -rf ~)/pipelock", `'/odd/$(rm -rf ~)/pipelock'`},
		{"/it's/here/pipelock", `'/it'\''s/here/pipelock'`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := shellQuote(tt.in); got != tt.want {
				t.Fatalf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStageAndVerifySignature_StageError(t *testing.T) {
	// dir does not exist -> writeFileQuiet fails.
	opts := &Options{CosignAvailable: func() bool { return false }, RunCommand: stubVersionRunner("")}
	_, err := opts.stageAndVerifySignature(context.Background(), &release{}, filepath.Join(t.TempDir(), "nope"), []byte("x"))
	if err == nil {
		t.Fatal("expected staging error")
	}
}
