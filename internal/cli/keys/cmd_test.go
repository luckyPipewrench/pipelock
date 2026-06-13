// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// runStatus executes `keys status` with args, capturing stdout via SetOut (the
// blessed CLI capture pattern, never os.Pipe).
func runStatus(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(append([]string{"status"}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

// TestStatusTextOutputDefaults exercises the human renderer with built-in
// defaults: every purpose appears, none claims present.
func TestStatusTextOutputDefaults(t *testing.T) {
	out, err := runStatus(t)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "Pipelock Signing Keys") {
		t.Errorf("missing header in output")
	}
	for _, purpose := range domsigning.KnownPurposes() {
		if !strings.Contains(out, purpose.String()) {
			t.Errorf("output missing purpose %q", purpose)
		}
	}
	if !strings.Contains(out, purposeLicense) {
		t.Errorf("output missing license-verification row")
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("output missing summary line")
	}
}

// TestStatusJSONShape exercises --json and asserts the decoded shape.
func TestStatusJSONShape(t *testing.T) {
	out, err := runStatus(t, "--json")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var report keyStatusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v\noutput: %s", err, out)
	}
	want := len(domsigning.KnownPurposes()) + 1
	if len(report.Keys) != want {
		t.Errorf("json keys = %d, want %d", len(report.Keys), want)
	}
	total := report.Summary.OK + report.Summary.Warn + report.Summary.Info + report.Summary.Fail
	if total != len(report.Keys) {
		t.Errorf("summary total %d != keys %d", total, len(report.Keys))
	}
}

// TestStatusConfigFlag proves --config loads a real config and resolves a
// present key through the full command path.
func TestStatusConfigFlag(t *testing.T) {
	dir := t.TempDir()
	path, fp := writeValidPrivateKey(t, dir, "receipt.key")

	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfgYAML := "mode: balanced\nflight_recorder:\n  signing_key_path: " + strconv.Quote(path) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, err := runStatus(t, "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("execute: %v\noutput: %s", err, out)
	}
	var report keyStatusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	item := findKey(t, report, purposeReceipt)
	if !item.Valid || item.Fingerprint != fp {
		t.Fatalf("want valid receipt key via --config, got %+v", item)
	}
}

// TestStatusBadConfigErrors proves a malformed --config path returns a non-nil
// error (exit code 2), not a silent pass.
func TestStatusBadConfigErrors(t *testing.T) {
	_, err := runStatus(t, "--config", filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

// TestRootBannerMessage exercises both branches of the root caveat. We can only
// assert the non-root branch deterministically in CI; if the suite runs as
// root, assert the banner is the expected text instead.
func TestRootBannerMessage(t *testing.T) {
	got := rootBannerMessage()
	if os.Geteuid() == 0 {
		if got != rootBannerText {
			t.Errorf("running as root: banner = %q, want %q", got, rootBannerText)
		}
		return
	}
	if got != "" {
		t.Errorf("non-root: banner = %q, want empty", got)
	}
}

// TestReadabilityDeniedNonRoot covers a key file whose mode denies read to the
// owner. Skipped under root, where DAC is bypassed and the file reads anyway —
// exactly the caveat the root banner documents.
func TestReadabilityDeniedNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: DAC bypassed, readability check is not meaningful (see root banner)")
	}
	dir := t.TempDir()
	path, _ := writeValidPrivateKey(t, dir, "noread.key")
	// 0o000: owner cannot read. The perm gate (0o037 mask) does NOT trip on
	// 0o000, so the code proceeds to load, which fails to open -> fail+unreadable.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) // let TempDir cleanup remove it

	item := finishPrivateKeyFile(keyStatusItem{Purpose: purposeReceipt, SourceKind: sourceConfigPrivate}, path, "absent")
	if !item.Present {
		t.Fatalf("file exists, want present=true; got %+v", item)
	}
	if item.Readable {
		t.Errorf("0o000 file must be unreadable to owner")
	}
	if item.Valid {
		t.Errorf("unreadable file cannot be valid")
	}
	if item.Status != statusFail {
		t.Errorf("status = %q, want fail", item.Status)
	}
}

// TestParsePublicKeyHexRejectsWrongLength guards the helper directly.
func TestParsePublicKeyHexRejectsWrongLength(t *testing.T) {
	if _, err := parsePublicKeyHex("abcd"); !errors.Is(err, errInvalidPublicKeyLen) {
		t.Errorf("short hex error = %v, want errInvalidPublicKeyLen", err)
	}
	if _, err := parsePublicKeyHex("zz"); err == nil {
		t.Error("want error for non-hex")
	}
}

// TestAppendNote covers the small join helper.
func TestAppendNote(t *testing.T) {
	cases := []struct{ name, a, b, want string }{
		{"empty_existing", "", "x", "x"},
		{"empty_add", "x", "", "x"},
		{"join", "a", "b", "a; b"},
		{"both_empty", "", "", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := appendNote(c.a, c.b); got != c.want {
				t.Errorf("appendNote(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
			}
		})
	}
}
