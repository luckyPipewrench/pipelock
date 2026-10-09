// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
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

const maxSummarySamples = 1000

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
	if *root == "" || *samples < 1 || *samples > maxSummarySamples {
		return "", fmt.Errorf("--root and --samples from 1 to %d are required", maxSummarySamples)
	}
	modeList := strings.Split(*modes, ",")
	seenModes := map[string]bool{}
	for _, mode := range modeList {
		if (mode != modeOff && mode != modeBest && mode != modeRequired) || seenModes[mode] {
			return "", fmt.Errorf("invalid or repeated mode %q", mode)
		}
		seenModes[mode] = true
	}
	p := summaryParams{root: *root, samples: *samples, modes: modeList, cpus: cpuList, chains: chainList}
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
	if p.samples < 1 || p.samples > maxSummarySamples {
		return fmt.Errorf("--samples must be from 1 to %d", maxSummarySamples)
	}
	var rows [][]string
	failed := false
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
						status, statusErr := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(path)), "scope.exit"))
						if statusErr != nil || strings.TrimSpace(string(status)) != "0" {
							r.Integrity.fail("matrix scope did not exit successfully")
							r.Performance.invalidate("matrix scope did not exit successfully")
						}
						results = append(results, r)
					}
				}
				row := summaryRow(cores, chains, mode, p.samples, results)
				if row[4] != verdictPass || row[6] != "0" {
					failed = true
				}
				rows = append(rows, row)
			}
		}
	}
	path := filepath.Clean(filepath.Join(p.root, "summary.csv"))
	out, err := os.CreateTemp(filepath.Dir(path), ".summary-*.tmp")
	if err != nil {
		return fmt.Errorf("create summary temporary file: %w", err)
	}
	tempPath := out.Name()
	closed := false
	defer func() {
		if !closed {
			_ = out.Close()
		}
		_ = os.Remove(tempPath)
	}()
	w := csv.NewWriter(out)
	if err := w.Write(summaryColumns); err != nil {
		return fmt.Errorf("write summary header: %w", err)
	}
	if err := w.WriteAll(rows); err != nil {
		return fmt.Errorf("write summary rows: %w", err)
	}
	if err := out.Close(); err != nil {
		closed = true
		return fmt.Errorf("close summary temporary file: %w", err)
	}
	closed = true
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace summary: %w", err)
	}
	if failed {
		return errors.New("matrix contains unusable samples; see summary.csv")
	}
	return nil
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
	compatible := true
	baseline := sampleIdentity(results[0])
	runTags := make(map[string]bool, len(results))
	for _, r := range results {
		perf, integ := r.Performance, r.Integrity
		if r.Inputs.Workload.Tag == "" || runTags[r.Inputs.Workload.Tag] {
			compatible = false
		}
		runTags[r.Inputs.Workload.Tag] = true
		if r.SchemaVersion != resultSchemaVersion || r.Inputs.Harness.ContractVersion != harnessContractVersion || r.Mode != mode || r.ReceiptChains != chains || !matchesCPU(r.Inputs.Host, cores) || !hasSampleFingerprints(r) || sampleIdentity(r) != baseline {
			compatible = false
		}
		if integ.Verdict != verdictPass || (integ.Verify.Ran && integ.Verify.Exit != 0) {
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
		configs = append(configs, r.Inputs.Config.CanonicalSHA256)
		binaries = append(binaries, r.Inputs.Binary.SHA256)
	}
	verdict := verdictPass
	if failures > 0 || !compatible {
		verdict = verdictFail
	}
	sorted := append([]float64(nil), rps...)
	sort.Float64s(sorted)
	row = append(row,
		verdict, strconv.Itoa(failures), strconv.Itoa(perfInvalid),
		f1(median(rps)), f1(sorted[0]), f1(sorted[len(sorted)-1]),
		f1(windowMin), f1(median(windowMedian)),
		f1(median(p95)), f1(median(p99)), strconv.FormatFloat(median(cpu), 'f', 2, 64),
		strconv.Itoa(missing), strconv.Itoa(errs), strconv.Itoa(bodyErrs), strconv.Itoa(verifyFail),
		same(rulesModes), short(same(configs)), short(same(binaries)),
	)
	if failures > 0 || perfInvalid > 0 || !compatible {
		for i := 7; i <= 14; i++ {
			row[i] = ""
		}
		if !compatible {
			row[6] = strconv.Itoa(samples)
		}
	}
	return row
}

func hasSampleFingerprints(r result) bool {
	for _, digest := range []string{r.Inputs.Harness.SourceSHA256, r.Inputs.Binary.SHA256, r.Inputs.Config.CanonicalSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return false
		}
	}
	return true
}

// sampleIdentity compares the full pinned inputs before any display shortening.
// Run paths and random run tags do not describe the measurement population.
func sampleIdentity(r result) [32]byte {
	inputs := r.Inputs
	inputs.Config.Path, inputs.Config.SHA256, inputs.Config.YAML = "", "", ""
	inputs.Env.Pinned = nil
	inputs.Env.DroppedCount = 0
	inputs.Rules.Source, inputs.Rules.Dir = "", ""
	inputs.Rules.ProxyLogLines = nil
	inputs.Workload.Tag = ""
	// systemd gives each sample a fresh scope name; compare the quota itself.
	if quota, _, ok := strings.Cut(inputs.Host.CgroupCPUQuota, " us ("); ok {
		inputs.Host.CgroupCPUQuota = quota
	}
	data, _ := json.Marshal(struct {
		Inputs                        inputsReport
		Requests, Warmup, Concurrency int
	}{inputs, r.Requests, r.WarmupRequests, r.Concurrency})
	return sha256.Sum256(data)
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

// matchesCPU binds the matrix label to the observed quota and scheduling inputs.
func matchesCPU(host hostReport, cores int) bool {
	if cores < 1 || host.HarnessGOMAXPROCS != cores || host.ChildGOMAXPROCS != strconv.Itoa(cores) {
		return false
	}
	quota, _, ok := strings.Cut(host.CgroupCPUQuota, " us (")
	if !ok {
		return false
	}
	numerator, denominator, ok := strings.Cut(quota, "/")
	if !ok {
		return false
	}
	q, period, ok := parseCPUQuotaRatio(numerator, denominator)
	return ok && q/period == int64(cores) && q%period == 0
}
