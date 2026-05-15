package harness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseKB(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want uint64
	}{
		{"VmRSS:   12345 kB", 12345},
		{"VmPeak:  98765 kB", 98765},
		{"VmRSS:0 kB", 0},
		{"VmRSS:", 0},        // no value
		{"VmRSS: abc kB", 0}, // non-numeric
		{"", 0},
	}
	for _, tc := range cases {
		got := parseKB(tc.line)
		if got != tc.want {
			t.Errorf("parseKB(%q)=%d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestPercentileKB(t *testing.T) {
	t.Parallel()
	vals := []uint64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	cases := []struct {
		p    int
		want uint64
	}{
		{50, 50},  // ceil(0.5*10)=5 -> 50
		{95, 100}, // ceil(0.95*10)=10 -> 100
		{99, 100}, // ceil(0.99*10)=10 -> 100
		{100, 100},
	}
	for _, tc := range cases {
		got := percentileKB(vals, tc.p)
		if got != tc.want {
			t.Errorf("percentile p%d: got %d, want %d", tc.p, got, tc.want)
		}
	}
}

func TestPercentileKB_Empty(t *testing.T) {
	t.Parallel()
	if got := percentileKB(nil, 99); got != 0 {
		t.Errorf("empty: got %d, want 0", got)
	}
}

func TestReadProcStatus_Self(t *testing.T) {
	t.Parallel()
	// Reading our own /proc/<pid>/status must succeed and report nonzero RSS.
	got, err := readProcStatus(os.Getpid())
	if err != nil {
		t.Fatalf("readProcStatus(self): %v", err)
	}
	if got.RSSKB == 0 {
		t.Error("RSSKB=0 for self — proc reader is broken")
	}
}

func TestReadProcStatus_NonexistentPID(t *testing.T) {
	t.Parallel()
	_, err := readProcStatus(0x7FFFFFFF) // far above any real PID
	if err == nil {
		t.Error("expected error for nonexistent pid")
	}
}

func TestParsePromFloatBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want uint64
	}{
		{"go_memstats_heap_alloc_bytes 1.5e+07", 15000000},
		{"go_memstats_heap_sys_bytes 33554432", 33554432},
		{"go_goroutines 17", 17},
		{"process_resident_memory_bytes 4.21748736e+07", 42174873},
		{"go_memstats_heap_alloc_bytes 0", 0},
		{"name -1", 0}, // negative clamps to zero
		{"name NaN", 0},
		{"name +Inf", 0},
		{"name not_a_num", 0},
		{"no_space_here", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := parsePromFloatBytes(tc.line)
		if got != tc.want {
			t.Errorf("parsePromFloatBytes(%q)=%d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestSummarizeMemory_UsesOnlySuccessfulRuntimeSamples(t *testing.T) {
	t.Parallel()
	got := summarizeMemory(MemoryResult{
		Samples: []MemorySample{
			{RSSKB: 10, VmPeakKB: 100, HeapAllocBytes: 4 * 1024, HeapSysBytes: 12 * 1024, Goroutines: 9},
			{RSSKB: 30, VmPeakKB: 110}, // failed scrape: RSS-only sample
		},
	})
	if !got.MetricsScraped {
		t.Fatal("MetricsScraped=false, want true when at least one runtime scrape succeeded")
	}
	if got.MeanRSSKB != 20 {
		t.Errorf("MeanRSSKB=%d, want 20", got.MeanRSSKB)
	}
	if got.MeanHeapAllocKB != 4 || got.P99HeapAllocKB != 4 {
		t.Errorf("heap alloc aggregates got mean=%d p99=%d, want 4/4", got.MeanHeapAllocKB, got.P99HeapAllocKB)
	}
	if got.MaxHeapSysKB != 12 {
		t.Errorf("MaxHeapSysKB=%d, want 12", got.MaxHeapSysKB)
	}
	if got.MaxGoroutines != 9 {
		t.Errorf("MaxGoroutines=%d, want 9", got.MaxGoroutines)
	}
}

func TestSummarizeMemory_NoRuntimeSamples(t *testing.T) {
	t.Parallel()
	got := summarizeMemory(MemoryResult{
		MetricsScraped: true,
		Samples:        []MemorySample{{RSSKB: 10}, {RSSKB: 30}},
	})
	if got.MetricsScraped {
		t.Fatal("MetricsScraped=true, want false when no runtime fields were populated")
	}
	if got.MeanHeapAllocKB != 0 || got.P99HeapAllocKB != 0 || got.MaxGoroutines != 0 {
		t.Errorf("runtime aggregates should stay zero, got %+v", got)
	}
}

func TestScrapeRuntimeMetrics_Success(t *testing.T) {
	t.Parallel()
	body := `# HELP go_memstats_heap_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 1.234e+07
# HELP go_memstats_heap_sys_bytes Number of bytes obtained from system.
go_memstats_heap_sys_bytes 4.5e+07
go_memstats_heap_inuse_bytes 1.5e+07
go_goroutines 23
process_resident_memory_bytes 5e+07
pipelock_requests_total 99
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	got, err := scrapeRuntimeMetrics(context.Background(), srv.Client(), srv.URL+"/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	want := runtimeMetrics{
		HeapAllocBytes:  12340000,
		HeapSysBytes:    45000000,
		HeapInuseBytes:  15000000,
		Goroutines:      23,
		ProcessRSSBytes: 50000000,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestScrapeRuntimeMetrics_NonOK(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	_, err := scrapeRuntimeMetrics(context.Background(), srv.Client(), srv.URL+"/metrics")
	if err == nil {
		t.Error("expected error on 503")
	}
}

func TestScrapeRuntimeMetrics_MissingRuntimeMetric(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("go_memstats_heap_alloc_bytes 123\n"))
	}))
	defer srv.Close()
	_, err := scrapeRuntimeMetrics(context.Background(), srv.Client(), srv.URL+"/metrics")
	if err == nil {
		t.Fatal("expected error when required runtime metrics are missing")
	}
	if !strings.Contains(err.Error(), "missing runtime metrics") {
		t.Fatalf("expected missing runtime metrics error, got %v", err)
	}
}

func TestScrapeRuntimeMetrics_RespectsContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the connection until the client gives up so we exercise the
		// context-cancel path in scrapeRuntimeMetrics.
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := scrapeRuntimeMetrics(ctx, srv.Client(), srv.URL+"/metrics")
	if err == nil {
		t.Error("expected error on canceled context")
	}
}
