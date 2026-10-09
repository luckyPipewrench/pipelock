// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func fakeResult(rps, windowMin, windowMedian float64, integrity, performance string) result {
	r := result{Mode: modeRequired}
	r.Performance = performanceReport{
		Verdict: performance, RequestsPerSecond: rps, CPUCores: 2,
		Latency: latencyReport{P95MS: 10, P99MS: 20},
		Windows: windowsReport{MinRPS: windowMin, MedianRPS: windowMedian},
	}
	r.Integrity = integrityReport{Verdict: integrity, Verify: verifyReport{Ran: true}}
	r.Inputs.Rules.Mode = rulesEmpty
	r.Inputs.Config.CanonicalSHA256 = "aaaaaaaaaaaaaaaaaaaa"
	r.Inputs.Binary.SHA256 = "bbbbbbbbbbbbbbbbbbbb"
	return r
}

func putResult(t *testing.T, root string, cores, chains, sample int, mode string, r result) {
	t.Helper()
	name := mode
	if chains > 1 {
		name = "chains-" + strconv.Itoa(chains) + "-" + mode
	}
	dir := filepath.Join(root, "cpu-"+strconv.Itoa(cores), "chains-"+strconv.Itoa(chains), "sample-"+strconv.Itoa(sample), name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeResult(dir, &r); err != nil {
		t.Fatal(err)
	}
}

func readSummary(t *testing.T, root string) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(filepath.Join(root, "summary.csv")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for _, rec := range records[1:] {
		row := map[string]string{}
		for i, col := range records[0] {
			row[col] = rec[i]
		}
		out[row["cpu_cores"]+"/"+row["chains"]+"/"+row["mode"]] = row
	}
	return out
}

func TestSummaryAggregatesVerdictsAndWindows(t *testing.T) {
	root := t.TempDir()
	putResult(t, root, 2, 1, 1, modeRequired, fakeResult(100, 80, 95, verdictPass, perfMeasured))
	putResult(t, root, 2, 1, 2, modeRequired, fakeResult(300, 60, 290, verdictPass, perfMeasured))
	putResult(t, root, 2, 1, 3, modeRequired, fakeResult(200, 90, 190, verdictPass, perfMeasured))
	bad := fakeResult(50, 40, 45, verdictFail, perfInvalid)
	bad.Integrity.ReceiptMissing = 7
	bad.Performance.BodyReadErrors = 2
	bad.Integrity.Verify.Exit = 1
	bad.Inputs.Config.CanonicalSHA256 = "cccccccccccccccccccc"
	putResult(t, root, 2, 2, 1, modeRequired, bad)
	putResult(t, root, 2, 2, 2, modeRequired, fakeResult(60, 50, 55, verdictPass, perfMeasured))

	err := writeSummary(summaryParams{root: root, samples: 3, modes: []string{modeRequired}, cpus: []int{2}, chains: []int{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	rows := readSummary(t, root)

	good := rows["2/1/required"]
	want := map[string]string{
		"integrity": "pass", "integrity_failures": "0", "performance_invalid": "0",
		"median_req_s": "200.0", "min_req_s": "100.0", "max_req_s": "300.0",
		"window_min_req_s": "60.0", "window_median_req_s": "190.0",
		"missing": "0", "rules": "empty", "config_canonical_sha256": "aaaaaaaaaaaa", "binary_sha256": "bbbbbbbbbbbb",
	}
	for col, v := range want {
		if good[col] != v {
			t.Errorf("2/1/required %s = %q, want %q", col, good[col], v)
		}
	}

	// One failed sample and one sample whose result.json is absent.
	chained := rows["2/2/required"]
	want = map[string]string{
		"integrity": "fail", "integrity_failures": "2", "performance_invalid": "2",
		"missing": "7", "body_read_errors": "2", "verify_failures": "1", "config_canonical_sha256": "mixed",
		"window_min_req_s": "40.0",
	}
	for col, v := range want {
		if chained[col] != v {
			t.Errorf("2/2/required %s = %q, want %q", col, chained[col], v)
		}
	}
}

func TestSummaryMissingCellFails(t *testing.T) {
	root := t.TempDir()
	if err := writeSummary(summaryParams{root: root, samples: 2, modes: []string{modeBest}, cpus: []int{4}, chains: []int{8}}); err != nil {
		t.Fatal(err)
	}
	row := readSummary(t, root)["4/8/best"]
	if row["integrity"] != "missing" || row["integrity_failures"] != "2" || row["performance_invalid"] != "2" {
		t.Fatalf("a cell with no result passed: %v", row)
	}
}

func TestSummarizeCommandValidatesInput(t *testing.T) {
	root := t.TempDir()
	putResult(t, root, 4, 1, 1, modeOff, fakeResult(10, 9, 10, verdictPass, perfMeasured))
	path, err := summarizeCommand([]string{"--root", root, "--samples", "1", "--modes", "off", "--cpus", "4", "--chains", "1"})
	if err != nil || filepath.Base(path) != "summary.csv" {
		t.Fatalf("summarizeCommand = %q, %v", path, err)
	}
	for _, bad := range [][]string{
		{},
		{"--root", root, "--samples", "0"},
		{"--root", root, "--cpus", "two"},
		{"--root", root, "--chains", "0"},
	} {
		if _, err := summarizeCommand(bad); err == nil {
			t.Fatalf("summarizeCommand(%v) accepted bad input", bad)
		}
	}
}
