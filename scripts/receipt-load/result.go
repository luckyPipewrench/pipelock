// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	resultSchemaVersion = 2

	perfMeasured = "measured"
	perfInvalid  = "invalid"
)

// result is the contents of result.json. Performance and integrity are
// separate verdicts: a fast run that lost receipts is not a good run, and an
// intact run that errored is not a usable measurement.
type result struct {
	SchemaVersion  int               `json:"schema_version"`
	Mode           string            `json:"mode"`
	ReceiptChains  int               `json:"receipt_chains"`
	Requests       int               `json:"requests"`
	WarmupRequests int               `json:"warmup_requests"`
	Concurrency    int               `json:"concurrency"`
	Inputs         inputsReport      `json:"inputs"`
	Performance    performanceReport `json:"performance"`
	Integrity      integrityReport   `json:"integrity"`
}

type inputsReport struct {
	Harness  harnessReport  `json:"harness"`
	Binary   binaryReport   `json:"binary"`
	Config   configReport   `json:"config"`
	Env      envReport      `json:"env"`
	Rules    rulesReport    `json:"rules"`
	Workload workloadReport `json:"workload"`
	Host     hostReport     `json:"host"`
}

type workloadReport struct {
	Seed          uint64  `json:"seed"`
	Tag           string  `json:"tag"`
	KeyParam      string  `json:"key_param"`
	BlockEvery    int     `json:"block_every"`
	BlockOffset   int     `json:"block_offset"`
	WindowSeconds float64 `json:"window_seconds"`
}

type latencyReport struct {
	Samples int     `json:"samples"`
	P50MS   float64 `json:"p50_ms"`
	P95MS   float64 `json:"p95_ms"`
	P99MS   float64 `json:"p99_ms"`
	MaxMS   float64 `json:"max_ms"`
}

type windowsReport struct {
	WindowSeconds float64      `json:"window_seconds"`
	FullWindows   int          `json:"full_windows"`
	MinRPS        float64      `json:"min_requests_per_second"`
	MedianRPS     float64      `json:"median_requests_per_second"`
	MaxRPS        float64      `json:"max_requests_per_second"`
	Rates         []windowRate `json:"rates"`
}

type performanceReport struct {
	Verdict           string         `json:"verdict"`
	Reasons           []string       `json:"reasons"`
	Seconds           float64        `json:"seconds"`
	RequestsPerSecond float64        `json:"requests_per_second"`
	Latency           latencyReport  `json:"latency"`
	Windows           windowsReport  `json:"windows"`
	Allowed           int            `json:"allowed"`
	Blocked           int            `json:"blocked"`
	Unexpected        int            `json:"unexpected"`
	Errors            int            `json:"errors"`
	BodyReadErrors    int            `json:"body_read_errors"`
	NotRun            int            `json:"not_run"`
	StatusCounts      map[int]int    `json:"status_counts"`
	ResponseSamples   map[int]string `json:"response_samples"`
	CPUSeconds        float64        `json:"cpu_seconds"`
	CPUCores          float64        `json:"cpu_cores_average"`
	RSSStartBytes     int64          `json:"rss_start_bytes"`
	RSSEndBytes       int64          `json:"rss_end_bytes"`
	RSSPeakBytes      int64          `json:"rss_peak_bytes"`
	EvidenceBytes     int64          `json:"evidence_bytes"`
	EvidenceAtStart   int64          `json:"evidence_bytes_at_measurement_start"`
	FlushLagMS        float64        `json:"last_receipt_after_last_response_ms"`
	RecorderFileLagMS float64        `json:"last_recorder_file_write_after_last_response_ms"`
}

func (p *performanceReport) invalidate(reason string) {
	p.Verdict = perfInvalid
	p.Reasons = append(p.Reasons, reason)
}

// summarizeMeasured turns the measured phase's per-request outcomes into the
// performance report. Latency spans the full body read, and a request that
// failed at the transport or while reading its body contributes no latency
// sample.
func summarizeMeasured(plan workload, phase phaseResult, window time.Duration, samples map[int]string) performanceReport {
	p := performanceReport{
		Verdict: perfMeasured, Reasons: []string{},
		StatusCounts: map[int]int{}, ResponseSamples: samples,
		Seconds: phase.elapsed.Seconds(),
	}
	latency := make([]int64, 0, len(phase.outcomes))
	doneAt := make([]int64, 0, len(phase.outcomes))
	for index, out := range phase.outcomes {
		if !out.ran {
			p.NotRun++
			continue
		}
		doneAt = append(doneAt, out.doneAtNS)
		blocked := plan.blocked(plan.slot(phaseMeasure, index))
		switch {
		case out.transportErr:
			p.Errors++
			p.StatusCounts[0]++
			continue
		case out.bodyReadErr:
			p.BodyReadErrors++
			p.StatusCounts[out.status]++
			continue
		}
		p.StatusCounts[out.status]++
		latency = append(latency, out.latencyNS)
		switch {
		case out.bodyMismatch:
			p.Unexpected++
		case blocked && out.status == http.StatusForbidden:
			p.Blocked++
		default:
			p.Allowed++
		}
	}
	if p.Seconds > 0 {
		p.RequestsPerSecond = float64(len(doneAt)) / p.Seconds
	}
	sorted := sortedCopy(latency)
	p.Latency = latencyReport{Samples: len(sorted), P50MS: quantileMS(sorted, 0.50), P95MS: quantileMS(sorted, 0.95), P99MS: quantileMS(sorted, 0.99), MaxMS: quantileMS(sorted, 1)}
	p.Windows = summarizeWindows(windowRates(doneAt, phase.elapsed, window), window)
	if p.Errors > 0 {
		p.invalidate("transport errors: throughput is not comparable")
	}
	if p.BodyReadErrors > 0 {
		p.invalidate("response bodies failed to read to the end")
	}
	if p.Unexpected > 0 {
		p.invalidate("responses did not match the request class")
	}
	if p.NotRun > 0 || phase.interrupted {
		p.invalidate("measured phase did not run to completion")
	}
	return p
}

// summarizeWindows reports min, median, and max over the full windows. A final
// partial window is listed but excluded from the statistics; when the run is
// shorter than one window the partial window is all there is, so it is used.
func summarizeWindows(rates []windowRate, window time.Duration) windowsReport {
	w := windowsReport{WindowSeconds: window.Seconds(), Rates: rates}
	if w.Rates == nil {
		w.Rates = []windowRate{}
	}
	var values []float64
	for _, r := range rates {
		if !r.Partial {
			values = append(values, r.RequestsPerSecond)
		}
	}
	w.FullWindows = len(values)
	if len(values) == 0 {
		for _, r := range rates {
			values = append(values, r.RequestsPerSecond)
		}
	}
	if len(values) == 0 {
		return w
	}
	sort.Float64s(values)
	w.MinRPS, w.MaxRPS = values[0], values[len(values)-1]
	mid := len(values) / 2
	if len(values)%2 == 1 {
		w.MedianRPS = values[mid]
	} else {
		w.MedianRPS = (values[mid-1] + values[mid]) / 2
	}
	return w
}

func writeResult(dir string, r *result) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "result.json"), append(data, '\n'), 0o600)
}
