// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var summaryColumns = []string{
	"cpu_cores", "chains", "mode", "samples",
	"integrity", "integrity_failures", "performance_invalid",
	"median_req_s", "min_req_s", "max_req_s",
	"window_min_req_s", "window_median_req_s",
	"median_p95_ms", "median_p99_ms", "median_cpu_cores",
	"missing", "errors", "body_read_errors", "verify_failures",
	"rules", "config_canonical_sha256", "binary_sha256",
}

type summaryParams struct {
	root    string
	samples int
	modes   []string
	cpus    []int
	chains  []int
}

// summarizeCommand implements `receipt-load summarize`, which turns a matrix
// directory of result.json files into summary.csv.
func summarizeCommand(args []string) (string, error) {
	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	root := fs.String("root", "", "matrix output directory")
	samples := fs.Int("samples", 1, "samples per cell")
	modes := fs.String("modes", "off,best,required", "comma-separated modes")
	cpus := fs.String("cpus", "2,4,8", "comma-separated CPU quotas")
	chains := fs.String("chains", "1,2,4,8", "comma-separated chain counts")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	cpuList, err := parseInts(*cpus)
	if err != nil {
		return "", fmt.Errorf("--cpus: %w", err)
	}
	chainList, err := parseInts(*chains)
	if err != nil {
		return "", fmt.Errorf("--chains: %w", err)
	}
	if *root == "" || *samples < 1 {
		return "", errors.New("--root and a positive --samples are required")
	}
	p := summaryParams{root: *root, samples: *samples, modes: strings.Split(*modes, ","), cpus: cpuList, chains: chainList}
	return filepath.Join(p.root, "summary.csv"), writeSummary(p)
}

func parseInts(list string) ([]int, error) {
	var out []int
	for _, field := range strings.Split(list, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("%q is not a positive integer", field)
		}
		out = append(out, n)
	}
	return out, nil
}

// writeSummary writes one row per CPU quota, chain count, and mode. A cell with
// an unreadable result.json counts as a failure of both verdicts: a missing
// result cannot have passed.
func writeSummary(p summaryParams) error {
	var rows [][]string
	for _, cores := range p.cpus {
		for _, chains := range p.chains {
			for _, mode := range p.modes {
				name := mode
				if chains > 1 {
					name = fmt.Sprintf("chains-%d-%s", chains, mode)
				}
				var results []result
				for sample := 1; sample <= p.samples; sample++ {
					path := filepath.Join(p.root, fmt.Sprintf("cpu-%d", cores), fmt.Sprintf("chains-%d", chains), fmt.Sprintf("sample-%d", sample), name, "result.json")
					if r, err := readResultFile(path); err == nil {
						results = append(results, r)
					}
				}
				rows = append(rows, summaryRow(cores, chains, mode, p.samples, results))
			}
		}
	}
	out, err := os.OpenFile(filepath.Clean(filepath.Join(p.root, "summary.csv")), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := csv.NewWriter(out)
	if err := w.Write(summaryColumns); err != nil {
		_ = out.Close()
		return err
	}
	if err := w.WriteAll(rows); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func readResultFile(path string) (result, error) {
	var r result
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(data, &r)
}

func summaryRow(cores, chains int, mode string, samples int, results []result) []string {
	row := []string{strconv.Itoa(cores), strconv.Itoa(chains), mode, strconv.Itoa(samples)}
	unreadable := samples - len(results)
	if len(results) == 0 {
		row = append(row, "missing", strconv.Itoa(samples), strconv.Itoa(samples))
		for len(row) < len(summaryColumns) {
			row = append(row, "")
		}
		return row
	}
	var rps, p95, p99, cpu, windowMedian []float64
	windowMin := results[0].Performance.Windows.MinRPS
	failures, perfInvalid, missing, errs, bodyErrs, verifyFail := unreadable, unreadable, 0, 0, 0, 0
	var rulesModes, configs, binaries []string
	for _, r := range results {
		perf, integ := r.Performance, r.Integrity
		if integ.Verdict != verdictPass {
			failures++
		}
		if perf.Verdict != perfMeasured {
			perfInvalid++
		}
		rps = append(rps, perf.RequestsPerSecond)
		p95 = append(p95, perf.Latency.P95MS)
		p99 = append(p99, perf.Latency.P99MS)
		cpu = append(cpu, perf.CPUCores)
		windowMedian = append(windowMedian, perf.Windows.MedianRPS)
		windowMin = min(windowMin, perf.Windows.MinRPS)
		missing += integ.ReceiptMissing
		errs += perf.Errors + perf.Unexpected
		bodyErrs += perf.BodyReadErrors
		if integ.Verify.Ran && integ.Verify.Exit != 0 {
			verifyFail++
		}
		rulesModes = append(rulesModes, r.Inputs.Rules.Mode)
		configs = append(configs, short(r.Inputs.Config.CanonicalSHA256))
		binaries = append(binaries, short(r.Inputs.Binary.SHA256))
	}
	verdict := verdictPass
	if failures > 0 {
		verdict = verdictFail
	}
	sorted := append([]float64(nil), rps...)
	sort.Float64s(sorted)
	return append(row,
		verdict, strconv.Itoa(failures), strconv.Itoa(perfInvalid),
		f1(median(rps)), f1(sorted[0]), f1(sorted[len(sorted)-1]),
		f1(windowMin), f1(median(windowMedian)),
		f1(median(p95)), f1(median(p99)), strconv.FormatFloat(median(cpu), 'f', 2, 64),
		strconv.Itoa(missing), strconv.Itoa(errs), strconv.Itoa(bodyErrs), strconv.Itoa(verifyFail),
		same(rulesModes), same(configs), same(binaries),
	)
}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// same returns the one value every sample shares, or "mixed" when they differ.
func same(values []string) string {
	for _, v := range values[1:] {
		if v != values[0] {
			return "mixed"
		}
	}
	return values[0]
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}
