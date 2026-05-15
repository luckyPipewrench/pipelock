package harness

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// MemoryConfig parameterizes the steady-state memory measurement.
type MemoryConfig struct {
	PID            int           // pipelock pid to sample
	Duration       time.Duration // total sampling duration
	SampleInterval time.Duration // time between samples
	// MetricsURL, if non-empty, is the http://host:port/metrics endpoint
	// exposed by pipelock's metrics_listen. The sampler scrapes it for Go
	// runtime + Prometheus process collectors each tick. Empty means RSS-only.
	MetricsURL string
}

// MemorySample is one snapshot. /proc fields come from /proc/<pid>/status;
// Go runtime fields come from scraping pipelock's /metrics endpoint when
// MetricsURL is set on the config.
type MemorySample struct {
	OffsetMs        uint64 `json:"offset_ms"`
	RSSKB           uint64 `json:"rss_kb"`
	VmPeakKB        uint64 `json:"vmpeak_kb"`
	VmSizeKB        uint64 `json:"vmsize_kb"`
	HeapAllocBytes  uint64 `json:"heap_alloc_bytes,omitempty"`
	HeapSysBytes    uint64 `json:"heap_sys_bytes,omitempty"`
	HeapInuseBytes  uint64 `json:"heap_inuse_bytes,omitempty"`
	Goroutines      uint64 `json:"goroutines,omitempty"`
	ProcessRSSBytes uint64 `json:"process_rss_bytes,omitempty"`
}

// MemoryResult is the rolled-up memory measurement.
type MemoryResult struct {
	DurationMs      uint64         `json:"duration_ms"`
	SampleInterval  uint64         `json:"sample_interval_ms"`
	MetricsScraped  bool           `json:"metrics_scraped"`
	Samples         []MemorySample `json:"samples,omitempty"`
	MeanRSSKB       uint64         `json:"mean_rss_kb"`
	P99RSSKB        uint64         `json:"p99_rss_kb"`
	MaxRSSKB        uint64         `json:"max_rss_kb"`
	MaxVmPeakKB     uint64         `json:"max_vmpeak_kb"`
	MeanHeapAllocKB uint64         `json:"mean_heap_alloc_kb,omitempty"`
	P99HeapAllocKB  uint64         `json:"p99_heap_alloc_kb,omitempty"`
	MaxHeapSysKB    uint64         `json:"max_heap_sys_kb,omitempty"`
	MaxGoroutines   uint64         `json:"max_goroutines,omitempty"`
	Error           string         `json:"error,omitempty"`
}

// RunMemory samples /proc/<pid>/status at the configured interval for the
// configured duration. If cfg.MetricsURL is set, each tick also scrapes
// pipelock's /metrics endpoint for Go runtime + Prometheus process collectors.
// Returns an aggregated MemoryResult.
//
// Callers are responsible for driving sustained traffic against the
// pipelock instance during the measurement window.
func RunMemory(ctx context.Context, cfg MemoryConfig) MemoryResult {
	res := MemoryResult{
		DurationMs:     durationMs(cfg.Duration),
		SampleInterval: durationMs(cfg.SampleInterval),
	}
	metricsClient := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(cfg.Duration)
	t := time.NewTicker(cfg.SampleInterval)
	defer t.Stop()
	start := time.Now()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			res.Error = ctx.Err().Error()
			return summarizeMemory(res)
		case <-t.C:
		}
		sample, err := readProcStatus(cfg.PID)
		if err != nil {
			res.Error = err.Error()
			return summarizeMemory(res)
		}
		if cfg.MetricsURL != "" {
			rt, scrapeErr := scrapeRuntimeMetrics(ctx, metricsClient, cfg.MetricsURL)
			if scrapeErr != nil {
				// Don't fail the whole run on a transient scrape miss; record
				// the error once and keep going with /proc-only data.
				if res.Error == "" {
					res.Error = "metrics scrape: " + scrapeErr.Error()
				}
			} else {
				sample.HeapAllocBytes = rt.HeapAllocBytes
				sample.HeapSysBytes = rt.HeapSysBytes
				sample.HeapInuseBytes = rt.HeapInuseBytes
				sample.Goroutines = rt.Goroutines
				sample.ProcessRSSBytes = rt.ProcessRSSBytes
				res.MetricsScraped = true
			}
		}
		sample.OffsetMs = durationMs(time.Since(start))
		res.Samples = append(res.Samples, sample)
	}
	return summarizeMemory(res)
}

// runtimeMetrics is the subset of Prometheus go_/process_ collectors that the
// bench cares about for steady-state memory reporting.
type runtimeMetrics struct {
	HeapAllocBytes  uint64
	HeapSysBytes    uint64
	HeapInuseBytes  uint64
	Goroutines      uint64
	ProcessRSSBytes uint64
}

// scrapeRuntimeMetrics fetches /metrics and parses the Prometheus text-format
// lines we care about. A hand-rolled parser is used instead of expfmt to keep
// the bench's runtime dependency surface small; the lines we read are simple
// `name value` pairs with no labels.
func scrapeRuntimeMetrics(ctx context.Context, c *http.Client, url string) (runtimeMetrics, error) {
	var out runtimeMetrics
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return out, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("metrics endpoint returned %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
	seen := map[string]bool{
		"go_memstats_heap_alloc_bytes":  false,
		"go_memstats_heap_sys_bytes":    false,
		"go_memstats_heap_inuse_bytes":  false,
		"go_goroutines":                 false,
		"process_resident_memory_bytes": false,
	}
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		switch {
		case strings.HasPrefix(line, "go_memstats_heap_alloc_bytes "):
			out.HeapAllocBytes = parsePromFloatBytes(line)
			seen["go_memstats_heap_alloc_bytes"] = true
		case strings.HasPrefix(line, "go_memstats_heap_sys_bytes "):
			out.HeapSysBytes = parsePromFloatBytes(line)
			seen["go_memstats_heap_sys_bytes"] = true
		case strings.HasPrefix(line, "go_memstats_heap_inuse_bytes "):
			out.HeapInuseBytes = parsePromFloatBytes(line)
			seen["go_memstats_heap_inuse_bytes"] = true
		case strings.HasPrefix(line, "go_goroutines "):
			out.Goroutines = parsePromFloatBytes(line)
			seen["go_goroutines"] = true
		case strings.HasPrefix(line, "process_resident_memory_bytes "):
			out.ProcessRSSBytes = parsePromFloatBytes(line)
			seen["process_resident_memory_bytes"] = true
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	var missing []string
	for name, ok := range seen {
		if !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return out, fmt.Errorf("metrics endpoint missing runtime metrics: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// parsePromFloatBytes parses the value column of a `name value` Prometheus
// text-format line, treating the value as a float and returning floor as
// uint64. Prometheus encodes integers as floats (e.g. "go_goroutines 17")
// so this is the correct general parser for our chosen metric set.
func parsePromFloatBytes(line string) uint64 {
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return 0
	}
	value := strings.TrimSpace(line[idx+1:])
	// Prometheus values can be in scientific notation; strconv.ParseFloat
	// handles that. Truncate to floor for the uint64 representation.
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0
	}
	const maxUint64 = ^uint64(0)
	if f > float64(maxUint64) {
		return maxUint64
	}
	return uint64(f)
}

// durationMs converts a time.Duration to milliseconds as an unsigned integer.
// Negative durations (which shouldn't occur in this bench) clamp to zero so
// the JSON output stays well-formed.
func durationMs(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return uint64(d / time.Millisecond)
}

func summarizeMemory(res MemoryResult) MemoryResult {
	if len(res.Samples) == 0 {
		return res
	}
	var rssSum, heapAllocSum uint64
	rssOnly := make([]uint64, 0, len(res.Samples))
	heapAllocOnly := make([]uint64, 0, len(res.Samples))
	for _, s := range res.Samples {
		rssSum += s.RSSKB
		rssOnly = append(rssOnly, s.RSSKB)
		if s.RSSKB > res.MaxRSSKB {
			res.MaxRSSKB = s.RSSKB
		}
		if s.VmPeakKB > res.MaxVmPeakKB {
			res.MaxVmPeakKB = s.VmPeakKB
		}
		if s.hasRuntimeMetrics() {
			heapAllocKB := s.HeapAllocBytes / 1024
			heapAllocSum += heapAllocKB
			heapAllocOnly = append(heapAllocOnly, heapAllocKB)
			if heapSysKB := s.HeapSysBytes / 1024; heapSysKB > res.MaxHeapSysKB {
				res.MaxHeapSysKB = heapSysKB
			}
			if s.Goroutines > res.MaxGoroutines {
				res.MaxGoroutines = s.Goroutines
			}
		}
	}
	res.MeanRSSKB = rssSum / uint64(len(res.Samples))
	res.P99RSSKB = percentileKB(rssOnly, 99)
	res.MetricsScraped = len(heapAllocOnly) > 0
	if res.MetricsScraped {
		res.MeanHeapAllocKB = heapAllocSum / uint64(len(heapAllocOnly))
		res.P99HeapAllocKB = percentileKB(heapAllocOnly, 99)
	}
	return res
}

func (s MemorySample) hasRuntimeMetrics() bool {
	return s.HeapAllocBytes != 0 ||
		s.HeapSysBytes != 0 ||
		s.HeapInuseBytes != 0 ||
		s.Goroutines != 0 ||
		s.ProcessRSSBytes != 0
}

func percentileKB(vals []uint64, p int) uint64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]uint64, len(vals))
	copy(sorted, vals)
	// Insertion sort is overkill here but keeps deps zero and handles tiny N
	// (the bench typically has 180 samples for a 30-min run at 10s cadence).
	for i := 1; i < len(sorted); i++ {
		v := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > v {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = v
	}
	idx := (p*len(sorted) + 99) / 100
	if idx < 1 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

// readProcStatus parses /proc/<pid>/status for VmRSS, VmPeak, VmSize.
func readProcStatus(pid int) (MemorySample, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), "status")
	f, err := os.Open(path) //nolint:gosec // /proc path constructed from numeric pid
	if err != nil {
		return MemorySample{}, fmt.Errorf("open status: %w", err)
	}
	defer func() { _ = f.Close() }()
	var sample MemorySample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			sample.RSSKB = parseKB(line)
		case strings.HasPrefix(line, "VmPeak:"):
			sample.VmPeakKB = parseKB(line)
		case strings.HasPrefix(line, "VmSize:"):
			sample.VmSizeKB = parseKB(line)
		}
	}
	if err := sc.Err(); err != nil {
		return MemorySample{}, err
	}
	return sample, nil
}

// parseKB extracts the kilobyte value from lines like "VmRSS:   12345 kB".
func parseKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}
