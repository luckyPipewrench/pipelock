// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewSummaryRefusesInvalidPopulation(t *testing.T) {
	for _, scenario := range []string{"failed", "mixed-config", "mixed-seed", "hash-prefix", "wrong-mode", "old-contract", "unknown-schema"} {
		t.Run(scenario, func(t *testing.T) {
			a := fakeResult(100, 80, 90, verdictPass, perfMeasured)
			b := fakeResult(900, 800, 850, verdictPass, perfMeasured)
			switch scenario {
			case "failed":
				b.Integrity.Verdict = verdictFail
			case "mixed-config":
				b.Inputs.Config.CanonicalSHA256 = "different"
			case "mixed-seed":
				b.Inputs.Workload.Seed = 2
			case "hash-prefix":
				b.Inputs.Binary.SHA256 += "different"
			case "wrong-mode":
				b.Mode = modeOff
			case "old-contract":
				b.Inputs.Harness.ContractVersion = "2"
			case "unknown-schema":
				b.SchemaVersion = 999
			}
			row := summaryRow(2, 1, modeRequired, 2, []result{a, b})
			if row[4] == verdictPass || row[7] != "" {
				t.Fatalf("unusable population reported integrity=%s median=%s", row[4], row[7])
			}
		})
	}
}

func TestReviewShellFailures(t *testing.T) {
	for _, code := range []string{"0", "7"} {
		t.Run("scope-exit-"+code, func(t *testing.T) {
			root := t.TempDir()
			scope := filepath.Join(root, "systemd-run")
			if err := os.WriteFile(scope, []byte("#!/bin/sh\nexit "+code+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(scope, 0o700); err != nil { //nolint:gosec // Test command must be executable.
				t.Fatal(err)
			}
			out := filepath.Join(root, "matrix")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "./matrix.sh", newFakePipelock(t, "clean"), newFakePipelock(t, "harness"), out, "1", "1") //nolint:gosec // Fixed script and test-owned paths.
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_MODES=off")
			log, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("missing cell passed: %s", log)
			}
			if _, err := os.Stat(filepath.Join(out, "summary.csv")); err != nil {
				t.Fatalf("failure packet missing: %v %s", err, log)
			}
			if rows := readSummary(t, out); len(rows) != 12 {
				t.Fatalf("got %d rows", len(rows))
			}
		})
	}
	t.Run("run-build-failure", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "make"), []byte("#!/bin/sh\nexit 9\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "make"), 0o700); err != nil { //nolint:gosec // Test command must be executable.
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "./run.sh", filepath.Join(root, "out")) //nolint:gosec // Fixed script and test-owned path.
		cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_REQUESTS=1")
		if log, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("build failure passed: %s", log)
		}
	})
}

func TestReviewWarmupErrorsInvalidateMeasurement(t *testing.T) {
	opt := smallOptions(t, newFakePipelock(t, "warmbadbody"))
	opt.requests, opt.warmup = 3, 3
	res, err := runMode(context.Background(), opt, modeOff)
	if err != nil {
		t.Fatal(err)
	}
	if res.Performance.Verdict != perfInvalid {
		t.Fatal("failed warmup reported a usable measurement")
	}
}

func TestReviewWindowDurationBoundary(t *testing.T) {
	rates := windowRates([]int64{int64(time.Millisecond)}, time.Second, time.Duration(1<<63-1))
	if len(rates) != 1 || rates[0].Requests != 1 || rates[0].Seconds != 1 {
		t.Fatalf("long valid window lost completions: %+v", rates)
	}
}

func TestReviewMatrixScopeFailureOverridesResult(t *testing.T) {
	root := t.TempDir()
	scope := filepath.Join(root, "systemd-run")
	if err := os.WriteFile(scope, []byte("#!/bin/sh\ncase \"$*\" in *\"/cpu-2/chains-1/\"*) shift 4; \"$@\" ;; esac\nexit 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(scope, 0o700); err != nil { //nolint:gosec // Test command must execute.
		t.Fatal(err)
	}
	out := filepath.Join(root, "matrix")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "./matrix.sh", newFakePipelock(t, "clean"), newFakePipelock(t, "harness"), out, "1", "1") //nolint:gosec // Fixed script and test-owned paths.
	cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "RECEIPT_LOAD_MODES=off")
	if log, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("failed scope exited zero: %s", log)
	}
	packet := readResult(t, filepath.Join(out, "cpu-2", "chains-1", "sample-1", "off"))
	if packet.Integrity.Verdict != verdictPass {
		t.Fatal("positive control did not write a passing result")
	}
	for key, row := range readSummary(t, out) {
		if row["integrity"] == verdictPass || row["median_req_s"] != "" {
			t.Fatalf("scope failure disappeared from %s: %v", key, row)
		}
	}
}

func TestReviewSummaryEquivalentScopes(t *testing.T) {
	a, b := fakeResult(100, 80, 90, verdictPass, perfMeasured), fakeResult(200, 180, 190, verdictPass, perfMeasured)
	a.Inputs.Host.CgroupCPUQuota = "200000/100000 us (/scope-one)"
	b.Inputs.Host.CgroupCPUQuota = "200000/100000 us (/scope-two)"
	row := summaryRow(2, 1, modeRequired, 2, []result{a, b})
	if row[4] != verdictPass || row[7] != "150.0" {
		t.Fatalf("equal quotas rejected: %v", row)
	}
	b.Inputs.Host.CgroupCPUQuota = "400000/100000 us (/scope-two)"
	row = summaryRow(2, 1, modeRequired, 2, []result{a, b})
	if row[4] != verdictFail || row[7] != "" {
		t.Fatalf("unequal quotas accepted: %v", row)
	}
}
