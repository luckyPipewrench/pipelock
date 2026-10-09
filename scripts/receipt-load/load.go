// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

const (
	// receiptHeader is the response header Pipelock uses to hand the recorded
	// ActionID back to the caller.
	receiptHeader = "X-Pipelock-Receipt"

	// maxBodyRead bounds how much of a response body the driver keeps for
	// verification. Anything longer is drained and counted as a mismatch.
	maxBodyRead = 64 << 10

	// bodySamples is how many leading responses keep their body text in the
	// result as evidence of what each class looks like.
	bodySamples = 3
)

// requestOutcome is what the client observed for one planned request. Latency
// runs from just before the request is issued until the response body has been
// read to its end, so it includes body transfer and not only time to headers.
type requestOutcome struct {
	ran           bool
	status        int
	transportErr  bool
	bodyReadErr   bool
	bodyMismatch  bool
	latencyNS     int64
	doneAtNS      int64
	receiptHeader string
}

// phaseResult holds every per-request outcome for a phase, indexed by the
// per-phase request index, plus the monotonic wall time the phase took.
type phaseResult struct {
	outcomes    []requestOutcome
	elapsed     time.Duration
	samples     map[int]string
	interrupted bool
}

type loadParams struct {
	client      *http.Client
	plan        workload
	sinkAddr    string
	concurrency int
}

// runPhase issues count requests of one phase at the configured concurrency.
// Timestamps use time.Since on a time.Now() base, which reads the monotonic
// clock, so window boundaries cannot move with wall-clock adjustments.
func runPhase(ctx context.Context, p loadParams, phase byte, count int) phaseResult {
	res := phaseResult{outcomes: make([]requestOutcome, count), samples: make(map[int]string)}
	if count == 0 {
		return res
	}
	var samplesMu sync.Mutex
	jobs := make(chan int, p.concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for range p.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				slot := p.plan.slot(phase, index)
				out, body := p.issue(ctx, slot, start)
				res.outcomes[index] = out
				// Keep the first few bodies plus the first blocked one, so the
				// result shows what each response class actually looked like.
				if index < bodySamples || (index < blockEvery && p.plan.blocked(slot)) {
					samplesMu.Lock()
					res.samples[index] = string(body)
					samplesMu.Unlock()
				}
			}
		}()
	}
feed:
	for index := range count {
		select {
		case jobs <- index:
		case <-ctx.Done():
			res.interrupted = true
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	res.elapsed = time.Since(start)
	return res
}

func (p loadParams) issue(ctx context.Context, slot int, base time.Time) (requestOutcome, []byte) {
	out := requestOutcome{ran: true}
	target := "http://" + p.sinkAddr + p.plan.pathAndQuery(slot)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out.transportErr = true
		return out, nil
	}
	before := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		out.transportErr = true
		out.latencyNS = time.Since(before).Nanoseconds()
		out.doneAtNS = time.Since(base).Nanoseconds()
		return out, nil
	}
	body, readErr := readBody(resp.Body)
	_ = resp.Body.Close()
	out.latencyNS = time.Since(before).Nanoseconds()
	out.doneAtNS = time.Since(base).Nanoseconds()
	out.status = resp.StatusCode
	out.receiptHeader = resp.Header.Get(receiptHeader)
	switch {
	case readErr != nil:
		out.bodyReadErr = true
	case !bodyMatches(p.plan.blocked(slot), resp.StatusCode, body):
		out.bodyMismatch = true
	}
	return out, body
}

// readBody reads a response body to its end. A body longer than maxBodyRead is
// drained but truncated in the returned slice so a mismatch is still caught.
func readBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBodyRead))
	if err != nil {
		return body, err
	}
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		return body, err
	}
	if n > 0 {
		body = append(body, '+')
	}
	return body, nil
}

// bodyMatches reports whether a response is the expected class: an allowed
// request returns exactly the sink body, a blocked one returns the DLP block
// message naming the credential class.
func bodyMatches(blocked bool, status int, body []byte) bool {
	if blocked {
		return status == http.StatusForbidden && bytes.Contains(body, []byte("GitHub Token"))
	}
	return status == http.StatusOK && string(body) == sinkBody
}

// windowRate is the completion rate inside one fixed-width window of the
// measured phase. The final window is partial when the phase does not end on a
// window boundary; its rate uses its real duration.
type windowRate struct {
	Index             int     `json:"index"`
	StartSeconds      float64 `json:"start_seconds"`
	Seconds           float64 `json:"seconds"`
	Requests          int     `json:"requests"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Partial           bool    `json:"partial"`
}

// windowRates buckets completion offsets into fixed windows on the monotonic
// timeline of the phase.
func windowRates(doneAtNS []int64, elapsed, window time.Duration) []windowRate {
	if window <= 0 || elapsed <= 0 {
		return nil
	}
	count := int(elapsed / window)
	if elapsed%window != 0 {
		count++
	}
	if count == 0 {
		return nil
	}
	counts := make([]int, count)
	for _, at := range doneAtNS {
		bucket := int(time.Duration(at) / window)
		if bucket >= count {
			bucket = count - 1
		}
		if bucket < 0 {
			bucket = 0
		}
		counts[bucket]++
	}
	rates := make([]windowRate, count)
	for i := range count {
		span := window
		partial := false
		if remaining := elapsed - time.Duration(i)*window; remaining < window {
			span = remaining
			partial = true
		}
		rates[i] = windowRate{
			Index:             i,
			StartSeconds:      (time.Duration(i) * window).Seconds(),
			Seconds:           span.Seconds(),
			Requests:          counts[i],
			RequestsPerSecond: float64(counts[i]) / span.Seconds(),
			Partial:           partial,
		}
	}
	return rates
}

// quantileMS returns the p-quantile of a sorted nanosecond slice in
// milliseconds, or zero for an empty slice.
func quantileMS(sorted []int64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return float64(sorted[int(float64(len(sorted)-1)*p)]) / 1e6
}

func sortedCopy(values []int64) []int64 {
	out := append([]int64(nil), values...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
