// demo-metrics generates fake Prometheus metrics that simulate a fleet of
// pipelock instances. Run it, point Prometheus at the four ports, wait
// ~10 minutes, and screenshot the Grafana dashboard for marketing material.
//
// Usage:
//
//	go run . [-duration 15m]
//
// Ports:
//
//	:19091 — prod-copilot    (high-volume, clean traffic)
//	:19092 — dev-assistant   (moderate, occasional DLP hits)
//	:19093 — research-bot    (incident scenario with chain detection & kill switch)
//	:19094 — data-pipeline   (WebSocket-heavy streaming agent)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	duration := flag.Duration("duration", 15*time.Minute, "how long to run before auto-exit")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	agents := []struct {
		name     string
		port     int
		scenario func(context.Context, *pipelockMetrics)
	}{
		{"prod-copilot", 19091, scenarioProdCopilot},
		{"dev-assistant", 19092, scenarioDevAssistant},
		{"research-bot", 19093, scenarioResearchBot},
		{"data-pipeline", 19094, scenarioDataPipeline},
	}

	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runAgent(ctx, a.name, a.port, a.scenario)
		}()
	}

	fmt.Println("Pipelock demo metrics running:")
	for _, a := range agents {
		fmt.Printf("  %-20s http://localhost:%d/metrics\n", a.name, a.port)
	}
	if *duration > 0 {
		fmt.Printf("\nWill run for %s. Press Ctrl+C to stop early.\n", *duration)
	} else {
		fmt.Println("\nRunning until Ctrl+C (no timeout).")
	}
	fmt.Println("\nAdd to Prometheus scrape config:")
	fmt.Println("  - job_name: pipelock-demo")
	fmt.Println("    static_configs:")
	fmt.Println("      - targets:")
	for _, a := range agents {
		fmt.Printf("          - 'localhost:%d'  # %s\n", a.port, a.name)
	}

	<-ctx.Done()
	wg.Wait()
	fmt.Println("\nDone.")
}

// ---------------------------------------------------------------------------
// Agent runner
// ---------------------------------------------------------------------------

func runAgent(ctx context.Context, name string, port int, scenario func(context.Context, *pipelockMetrics)) {
	m := newPipelockMetrics()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("%s: %v", name, err)
		}
	}()

	scenario(ctx, m)
	_ = srv.Shutdown(context.Background())
}

// ---------------------------------------------------------------------------
// Metric registration — mirrors internal/metrics/metrics.go exactly
// ---------------------------------------------------------------------------

type pipelockMetrics struct {
	registry *prometheus.Registry

	requestsTotal  *prometheus.CounterVec
	requestLatency prometheus.Histogram
	scannerHits    *prometheus.CounterVec

	tunnelsTotal   *prometheus.CounterVec
	tunnelDuration prometheus.Histogram
	tunnelBytes    prometheus.Counter
	activeTunnels  prometheus.Gauge

	wsConnectionsTotal *prometheus.CounterVec
	wsDuration         prometheus.Histogram
	wsBytes            *prometheus.CounterVec
	activeWS           prometheus.Gauge
	wsFrames           *prometheus.CounterVec
	wsScanHits         *prometheus.CounterVec
	wsRedirectHints    prometheus.Counter

	killSwitchDenials  *prometheus.CounterVec
	chainDetections    *prometheus.CounterVec
	sessionAnomalies   *prometheus.CounterVec
	sessionEscalations *prometheus.CounterVec
	sessionsActive     prometheus.Gauge
	sessionsEvicted    prometheus.Counter
}

func newPipelockMetrics() *pipelockMetrics {
	reg := prometheus.NewRegistry()
	m := &pipelockMetrics{registry: reg}

	m.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "requests_total",
		Help: "Total number of fetch proxy requests by result.",
	}, []string{"result"})

	m.requestLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock", Name: "request_duration_seconds",
		Help:    "Fetch request latency in seconds.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	})

	m.scannerHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "scanner_hits_total",
		Help: "Total blocks by scanner type.",
	}, []string{"scanner"})

	m.tunnelsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "tunnels_total",
		Help: "Total CONNECT tunnels by result.",
	}, []string{"result"})

	m.tunnelDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock", Name: "tunnel_duration_seconds",
		Help:    "CONNECT tunnel duration in seconds.",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	})

	m.tunnelBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "tunnel_bytes_total",
		Help: "Total bytes transferred through CONNECT tunnels.",
	})

	m.activeTunnels = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock", Name: "active_tunnels",
		Help: "Current number of active CONNECT tunnels.",
	})

	m.wsConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "ws_connections_total",
		Help: "Total WebSocket proxy connections by result.",
	}, []string{"result"})

	m.wsDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock", Name: "ws_duration_seconds",
		Help:    "WebSocket connection duration in seconds.",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	})

	m.wsBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "ws_bytes_total",
		Help: "Total bytes transferred through WebSocket proxy.",
	}, []string{"direction"})

	m.activeWS = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock", Name: "ws_active_connections",
		Help: "Current number of active WebSocket proxy connections.",
	})

	m.wsFrames = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "ws_frames_total",
		Help: "Total WebSocket frames by type.",
	}, []string{"type"})

	m.wsScanHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "ws_scan_hits_total",
		Help: "Total WebSocket scan detections by scanner.",
	}, []string{"scanner"})

	m.wsRedirectHints = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "forward_ws_redirect_hint_total",
		Help: "CONNECT requests to known WebSocket API hosts.",
	})

	m.killSwitchDenials = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "kill_switch_denials_total",
		Help: "Total requests denied by the kill switch.",
	}, []string{"transport", "endpoint"})

	m.chainDetections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "chain_detections_total",
		Help: "Total tool call chain pattern detections.",
	}, []string{"pattern", "severity", "action"})

	m.sessionAnomalies = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "session_anomalies_total",
		Help: "Total session behavioral anomalies by type.",
	}, []string{"type"})

	m.sessionEscalations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "session_escalations_total",
		Help: "Total session enforcement escalations by transition.",
	}, []string{"from", "to"})

	m.sessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock", Name: "sessions_active",
		Help: "Current number of active tracked sessions.",
	})

	m.sessionsEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock", Name: "sessions_evicted_total",
		Help: "Total sessions evicted by TTL or capacity.",
	})

	reg.MustRegister(
		m.requestsTotal, m.requestLatency, m.scannerHits,
		m.tunnelsTotal, m.tunnelDuration, m.tunnelBytes, m.activeTunnels,
		m.wsConnectionsTotal, m.wsDuration, m.wsBytes, m.activeWS,
		m.wsFrames, m.wsScanHits, m.wsRedirectHints,
		m.killSwitchDenials, m.chainDetections,
		m.sessionAnomalies, m.sessionEscalations,
		m.sessionsActive, m.sessionsEvicted,
	)

	return m
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// jitter returns v ± up to frac*v (e.g., jitter(10, 0.2) → 8..12).
func jitter(v, frac float64) float64 {
	return v * (1 + frac*(2*rand.Float64()-1))
}

// maybe returns true with the given probability per second (called once/sec).
func maybe(probPerSec float64) bool {
	return rand.Float64() < probPerSec
}

// sinWave returns a value that oscillates between base±amplitude over period seconds.
func sinWave(elapsed, base, amplitude, period float64) float64 {
	return base + amplitude*math.Sin(2*math.Pi*elapsed/period)
}

// noisyGauge sets a gauge to base ± jitter, clamped to >= min.
func noisyGauge(g prometheus.Gauge, base, frac, min float64) {
	v := jitter(base, frac)
	if v < min {
		v = min
	}
	g.Set(math.Round(v))
}

// observeDuration adds n histogram observations drawn from a normal distribution.
func observeDuration(h prometheus.Histogram, n int, mean, stddev, min float64) {
	for range n {
		v := mean + stddev*rand.NormFloat64()
		if v < min {
			v = min
		}
		h.Observe(v)
	}
}

// tick runs fn every second until ctx is cancelled.
func tick(ctx context.Context, fn func(elapsed float64)) {
	start := time.Now()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(time.Since(start).Seconds())
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario 1: prod-copilot — High-volume coding assistant
//
// Heavy CONNECT tunnels to GitHub API, npm, PyPI. Very low block rate.
// No WebSocket. No security events. The "boring but healthy" agent.
// ---------------------------------------------------------------------------

func scenarioProdCopilot(ctx context.Context, m *pipelockMetrics) {
	m.sessionsActive.Set(12)
	m.activeTunnels.Set(5)

	tick(ctx, func(elapsed float64) {
		// Coding assistant — GitHub API, npm, docs. ~1 conn/sec avg.
		if maybe(sinWave(elapsed, 0.8, 0.3, 120)) {
			m.tunnelsTotal.WithLabelValues("completed").Inc()
			m.tunnelBytes.Add(jitter(80000, 0.3))
			m.tunnelDuration.Observe(math.Max(0.1, 2.5+1.2*rand.NormFloat64()))
		}

		// Very rare block — maybe 1 every few minutes
		if maybe(0.002) {
			m.tunnelsTotal.WithLabelValues("blocked").Inc()
			m.scannerHits.WithLabelValues("domain").Inc()
		}

		noisyGauge(m.activeTunnels, sinWave(elapsed, 3, 1, 120), 0.15, 1)
		noisyGauge(m.sessionsActive, 12, 0.06, 9)

		// Extremely rare DLP — maybe once in the whole demo
		if maybe(0.0003) {
			m.scannerHits.WithLabelValues("dlp").Inc()
		}

		if maybe(0.002) {
			m.sessionsEvicted.Inc()
		}
	})
}

// ---------------------------------------------------------------------------
// Scenario 2: dev-assistant — Developer helper with DLP catches
//
// Moderate tunnel traffic. Some plain HTTP too (internal APIs).
// Regular DLP hits from test API keys in prompts. A few domain blocks.
// Session anomalies occasionally.
// ---------------------------------------------------------------------------

func scenarioDevAssistant(ctx context.Context, m *pipelockMetrics) {
	m.sessionsActive.Set(8)
	m.activeTunnels.Set(4)

	tick(ctx, func(elapsed float64) {
		// Dev assistant — IDE, docs, internal APIs. ~0.5 conn/sec avg.
		if maybe(sinWave(elapsed, 0.45, 0.15, 75)) {
			m.tunnelsTotal.WithLabelValues("completed").Inc()
			m.tunnelBytes.Add(jitter(45000, 0.4))
			m.tunnelDuration.Observe(math.Max(0.05, 1.8+0.8*rand.NormFloat64()))
		}

		// Occasional domain block
		if maybe(0.003) {
			m.tunnelsTotal.WithLabelValues("blocked").Inc()
			m.scannerHits.WithLabelValues("domain").Inc()
		}

		// Some plain HTTP traffic (internal tool APIs)
		if maybe(0.3) {
			m.requestsTotal.WithLabelValues("allowed").Inc()
			m.requestLatency.Observe(jitter(0.08, 0.4))
		}
		if maybe(0.005) {
			m.requestsTotal.WithLabelValues("blocked").Inc()
			m.requestLatency.Observe(jitter(0.015, 0.3))
		}

		// DLP hits — dev testing with API keys, ~1 per minute
		if maybe(0.015) {
			m.scannerHits.WithLabelValues("dlp").Inc()
		}

		// Rare entropy scanner catch
		if maybe(0.003) {
			m.scannerHits.WithLabelValues("entropy").Inc()
		}

		// Occasional session anomaly
		if maybe(0.005) {
			types := []string{"rate_spike", "new_domain", "payload_size"}
			m.sessionAnomalies.WithLabelValues(types[rand.IntN(len(types))]).Inc()
		}

		// Very rare chain detection warning (not blocking)
		if maybe(0.0005) {
			m.chainDetections.WithLabelValues("scrape_aggregate_post", "medium", "warn").Inc()
		}

		// Gauges
		noisyGauge(m.activeTunnels, sinWave(elapsed, 2, 1, 75), 0.2, 1)
		noisyGauge(m.sessionsActive, 8, 0.08, 5)

		if maybe(0.002) {
			m.sessionsEvicted.Inc()
		}
	})
}

// ---------------------------------------------------------------------------
// Scenario 3: research-bot — Repeating incident scenario
//
// Cycles every 5 minutes (300s):
//   0:00–1:30  Normal baseline traffic
//   1:30–2:00  DLP burst (exfiltration attempt)
//   2:00–2:30  Chain detections + anomalies spike
//   2:30–3:00  Session escalation, kill switch fires
//   3:00–4:00  Kill switch active (deny all)
//   4:00–5:00  Recovery, elevated blocks
//
// Repeats — so in a 15-min window you get 3 visible incident arcs.
// ---------------------------------------------------------------------------

func scenarioResearchBot(ctx context.Context, m *pipelockMetrics) {
	m.sessionsActive.Set(10)
	m.activeTunnels.Set(6)

	tick(ctx, func(elapsed float64) {
		// Cycle every 300 seconds
		cycle := math.Mod(elapsed, 300)
		phase := classifyPhase(cycle)

		switch phase {
		case phaseBaseline:
			researchBaseline(m, elapsed)

		case phaseExfilAttempt:
			researchBaseline(m, elapsed)
			// DLP burst — exfiltration attempt
			if maybe(0.6) {
				m.scannerHits.WithLabelValues("dlp").Inc()
			}
			if maybe(0.3) {
				m.scannerHits.WithLabelValues("entropy").Inc()
			}
			// Elevated blocks
			if maybe(0.5) {
				m.tunnelsTotal.WithLabelValues("blocked").Inc()
				m.scannerHits.WithLabelValues("dlp").Inc()
			}
			// Anomalies start climbing
			if maybe(0.3) {
				m.sessionAnomalies.WithLabelValues("rate_spike").Inc()
			}

		case phaseChainDetection:
			researchBaseline(m, elapsed)
			// Chain detections — tool call attack sequences
			if maybe(0.25) {
				m.chainDetections.WithLabelValues("read_encode_exfil", "critical", "block").Inc()
			}
			if maybe(0.15) {
				m.chainDetections.WithLabelValues("scrape_aggregate_post", "high", "warn").Inc()
			}
			if maybe(0.1) {
				m.chainDetections.WithLabelValues("env_read_http_post", "critical", "block").Inc()
			}
			// Heavy DLP
			if maybe(0.4) {
				m.scannerHits.WithLabelValues("dlp").Inc()
			}
			// Heavy anomalies
			if maybe(0.5) {
				types := []string{"rate_spike", "payload_size", "new_domain", "pattern_deviation"}
				m.sessionAnomalies.WithLabelValues(types[rand.IntN(len(types))]).Inc()
			}
			// Escalation
			if cycle > 120 && cycle < 122 {
				m.sessionEscalations.WithLabelValues("warn", "high").Inc()
			}
			if cycle > 135 && cycle < 137 {
				m.sessionEscalations.WithLabelValues("high", "block").Inc()
			}

		case phaseKillSwitch:
			// Kill switch active — all traffic denied
			m.activeTunnels.Set(0)
			// Heavy denial traffic
			if maybe(0.9) {
				m.killSwitchDenials.WithLabelValues("connect", "/api/v1/data").Inc()
			}
			if maybe(0.5) {
				m.killSwitchDenials.WithLabelValues("http", "/upload").Inc()
			}
			if maybe(0.3) {
				m.killSwitchDenials.WithLabelValues("connect", "/internal/secrets").Inc()
			}
			// Sessions get evicted during lockdown
			if maybe(0.15) {
				m.sessionsEvicted.Inc()
			}
			noisyGauge(m.sessionsActive, 2, 0.3, 1)

		case phaseRecovery:
			// Traffic resumes cautiously
			rate := sinWave(elapsed, 3.0, 1.0, 60)
			n := int(math.Max(0, rate+rand.NormFloat64()*0.5))
			m.tunnelsTotal.WithLabelValues("completed").Add(float64(n))
			m.tunnelBytes.Add(float64(n) * jitter(25000, 0.3))
			observeDuration(m.tunnelDuration, n, 2.0, 1.0, 0.1)

			// Still elevated block rate
			if maybe(rate * 0.12) {
				m.tunnelsTotal.WithLabelValues("blocked").Inc()
				m.scannerHits.WithLabelValues("domain").Inc()
			}

			noisyGauge(m.activeTunnels, sinWave(elapsed, 4, 1.5, 60), 0.3, 1)
			noisyGauge(m.sessionsActive, 6, 0.15, 3)

			if maybe(0.05) {
				m.sessionAnomalies.WithLabelValues("new_domain").Inc()
			}
		}
	})
}

type incidentPhase int

const (
	phaseBaseline       incidentPhase = iota // 0–90s
	phaseExfilAttempt                        // 90–120s
	phaseChainDetection                      // 120–150s
	phaseKillSwitch                          // 150–240s
	phaseRecovery                            // 240–300s
)

func classifyPhase(cyclePos float64) incidentPhase {
	switch {
	case cyclePos < 90:
		return phaseBaseline
	case cyclePos < 120:
		return phaseExfilAttempt
	case cyclePos < 150:
		return phaseChainDetection
	case cyclePos < 240:
		return phaseKillSwitch
	default:
		return phaseRecovery
	}
}

func researchBaseline(m *pipelockMetrics, elapsed float64) {
	// ~0.6 conn/sec average during normal research
	if maybe(sinWave(elapsed, 0.6, 0.2, 60)) {
		m.tunnelsTotal.WithLabelValues("completed").Inc()
		m.tunnelBytes.Add(jitter(55000, 0.3))
		m.tunnelDuration.Observe(math.Max(0.1, 2.5+1.2*rand.NormFloat64()))
	}

	if maybe(0.003) {
		m.tunnelsTotal.WithLabelValues("blocked").Inc()
		m.scannerHits.WithLabelValues("domain").Inc()
	}

	noisyGauge(m.activeTunnels, sinWave(elapsed, 3, 1, 60), 0.2, 1)
	noisyGauge(m.sessionsActive, 10, 0.08, 6)
}

// ---------------------------------------------------------------------------
// Scenario 4: data-pipeline — WebSocket-heavy streaming agent
//
// Low tunnel traffic. Heavy WebSocket connections with frame inspection.
// WS scan hits from scanning streamed content. Some WS blocks.
// Shows all the WebSocket metrics in action.
// ---------------------------------------------------------------------------

func scenarioDataPipeline(ctx context.Context, m *pipelockMetrics) {
	m.sessionsActive.Set(6)
	m.activeTunnels.Set(3)
	m.activeWS.Set(4)

	tick(ctx, func(elapsed float64) {
		// Data pipeline — fewer but larger connections. ~1 conn/sec (bigger payloads).
		if maybe(sinWave(elapsed, 1.0, 0.4, 100)) {
			m.tunnelsTotal.WithLabelValues("completed").Inc()
			m.tunnelBytes.Add(jitter(120000, 0.3)) // Big payloads per connection
			m.tunnelDuration.Observe(math.Max(0.05, 1.5+0.6*rand.NormFloat64()))
		}

		// Very rare blocks
		if maybe(0.002) {
			m.tunnelsTotal.WithLabelValues("blocked").Inc()
			m.scannerHits.WithLabelValues("domain").Inc()
		}

		// WebSocket redirect hints — occasional
		if maybe(0.02) {
			m.wsRedirectHints.Inc()
		}

		// WebSocket connections — long-lived streaming, rare new ones
		if maybe(0.008) {
			m.wsConnectionsTotal.WithLabelValues("completed").Inc()
			m.wsDuration.Observe(jitter(300, 0.5)) // Long-lived
		}
		if maybe(0.001) {
			m.wsConnectionsTotal.WithLabelValues("blocked").Inc()
			m.wsDuration.Observe(jitter(12, 0.4))
			m.wsScanHits.WithLabelValues("dlp").Inc()
		}

		// Active WS connections 3–5
		noisyGauge(m.activeWS, sinWave(elapsed, 4, 1, 150), 0.15, 2)

		// Frame flow — streaming data (this is where throughput shows)
		textFrames := int(jitter(25, 0.2))
		binFrames := int(jitter(8, 0.3))
		m.wsFrames.WithLabelValues("text").Add(float64(textFrames))
		m.wsFrames.WithLabelValues("binary").Add(float64(binFrames))

		// WebSocket throughput — the pipeline's signature metric
		m.wsBytes.WithLabelValues("client_to_server").Add(jitter(30000, 0.25))
		m.wsBytes.WithLabelValues("server_to_client").Add(jitter(120000, 0.25))

		// Rare WS scan hits
		if maybe(0.003) {
			m.wsScanHits.WithLabelValues("dlp").Inc()
		}
		if maybe(0.001) {
			m.wsScanHits.WithLabelValues("prompt_injection").Inc()
		}

		// Occasional health check HTTP
		if maybe(0.15) {
			m.requestsTotal.WithLabelValues("allowed").Inc()
			m.requestLatency.Observe(jitter(0.02, 0.3))
		}
		if maybe(0.002) {
			m.requestsTotal.WithLabelValues("blocked").Inc()
			m.scannerHits.WithLabelValues("ssrf").Inc()
		}

		// Gauges
		noisyGauge(m.activeTunnels, sinWave(elapsed, 3, 1, 100), 0.3, 1)
		noisyGauge(m.sessionsActive, 6, 0.08, 3)

		// Rare anomaly from large payloads
		if maybe(0.003) {
			m.sessionAnomalies.WithLabelValues("payload_size").Inc()
		}

		if maybe(0.002) {
			m.sessionsEvicted.Inc()
		}
	})
}
