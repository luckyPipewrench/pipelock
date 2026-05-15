// Command bench-egress is the entry point for pipelock's agent-egress overhead
// benchmark. It drives traffic across five transports (HTTP, SSE, tool-chain,
// MCP stdio, WebSocket) directly against in-process mocks and through a
// pipelock subprocess, then emits a single JSON document with per-transport
// percentiles, cold-start measurements, and (optionally) steady-state memory.
//
// See bench/egress/README.md for the schema and reproduce instructions.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/bench/egress/harness"
)

// benchVersion is the schema version of the JSON output. Bump when adding,
// removing, or renaming top-level fields so consumers can detect drift.
const benchVersion = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bench-egress:", err)
		os.Exit(1)
	}
}

type flags struct {
	pipelockBinary string
	mcpStdioBinary string
	configDir      string
	output         string
	iterations     int
	warmup         int
	memoryDuration time.Duration
	memoryInterval time.Duration
	coldStartIter  int
	quick          bool
	release        bool
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.pipelockBinary, "pipelock-binary", "./pipelock", "path to pipelock binary")
	flag.StringVar(&f.mcpStdioBinary, "mcpstdio-binary", "./bench-mcpstdio", "path to bench mcpstdio mock binary")
	flag.StringVar(&f.configDir, "config-dir", "bench/egress/configs", "directory containing minimal.yaml / default.yaml / full.yaml")
	flag.StringVar(&f.output, "output", "bench/egress/results.json", "output JSON path")
	flag.IntVar(&f.iterations, "iterations", 0, "measured iterations per transport (overrides mode default)")
	flag.IntVar(&f.warmup, "warmup", 0, "warmup iterations per transport (overrides mode default)")
	flag.DurationVar(&f.memoryDuration, "memory-duration", 0, "steady-state memory sampling duration (0 = skip)")
	flag.DurationVar(&f.memoryInterval, "memory-interval", 10*time.Second, "memory sampling interval")
	flag.IntVar(&f.coldStartIter, "coldstart-iterations", 0, "cold-start restarts per config (overrides mode default)")
	flag.BoolVar(&f.quick, "quick", true, "quick mode: small iteration counts, no memory")
	flag.BoolVar(&f.release, "release", false, "release mode: full iteration counts, memory enabled (overrides --quick)")
	flag.Parse()
	if f.release {
		f.quick = false
		if f.iterations == 0 {
			f.iterations = 10000
		}
		if f.warmup == 0 {
			f.warmup = 500
		}
		if f.coldStartIter == 0 {
			f.coldStartIter = 10
		}
		if f.memoryDuration == 0 {
			f.memoryDuration = 30 * time.Minute
		}
	} else {
		if f.iterations == 0 {
			f.iterations = 500
		}
		if f.warmup == 0 {
			f.warmup = 50
		}
		if f.coldStartIter == 0 {
			f.coldStartIter = 3
		}
	}
	return f
}

func run() error {
	f := parseFlags()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Validate inputs early so we don't waste minutes before failing.
	if _, err := os.Stat(f.pipelockBinary); err != nil {
		return fmt.Errorf("pipelock binary %q: %w", f.pipelockBinary, err)
	}
	if _, err := os.Stat(f.mcpStdioBinary); err != nil {
		return fmt.Errorf("mcpstdio binary %q: %w", f.mcpStdioBinary, err)
	}
	configs, err := loadConfigSpecs(f.configDir)
	if err != nil {
		return err
	}

	report := newReport(f)

	// Phase 1: spawn pipelock with the default config for latency + memory.
	// metrics_listen is wired on a separate port so the memory sampler can
	// scrape Go runtime collectors alongside /proc/<pid>/status RSS.
	defaultCfg := configs[1].Path // minimal=0, default=1, full=2
	metricsPort, err := pickFreePort()
	if err != nil {
		return fmt.Errorf("pick metrics port: %w", err)
	}
	metricsListen := "127.0.0.1:" + strconv.Itoa(metricsPort)
	runtimeCfg, cleanup, err := materializeRuntimeConfig(defaultCfg, metricsListen)
	if err != nil {
		return fmt.Errorf("materialize runtime config: %w", err)
	}
	defer cleanup()

	listen, pipelockProc, pipelockPID, err := startPipelock(ctx, f.pipelockBinary, runtimeCfg)
	if err != nil {
		return fmt.Errorf("start pipelock for latency: %w", err)
	}

	pipelockURL := "http://" + listen
	metricsURL := "http://" + metricsListen + "/metrics"
	report.PipelockListen = listen
	report.PipelockMetricsListen = metricsListen
	report.LatencyConfigName = "default"
	report.LatencyConfigSHA256 = configs[1].SHA

	latencyCfg := harness.DefaultLatencyConfig(pipelockURL)
	latencyCfg.Iterations = f.iterations
	latencyCfg.Warmup = f.warmup

	fmt.Fprintf(os.Stderr, "[bench-egress] latency: %d iterations (warmup %d) through pipelock at %s\n",
		latencyCfg.Iterations, latencyCfg.Warmup, listen)

	report.Latency.HTTP = harness.RunHTTP(ctx, latencyCfg)
	report.Latency.SSE = harness.RunSSE(ctx, latencyCfg)
	report.Latency.Toolchain = harness.RunToolchain(ctx, latencyCfg)
	report.Latency.WebSocket = harness.RunWebSocket(ctx, latencyCfg)
	report.Latency.MCPStdio = harness.RunMCPStdio(ctx, latencyCfg, f.mcpStdioBinary, f.pipelockBinary, defaultCfg)

	// Memory measurement uses the same long-lived pipelock instance and
	// scrapes Go runtime collectors from the metrics endpoint each tick.
	if f.memoryDuration > 0 {
		fmt.Fprintf(os.Stderr, "[bench-egress] memory: %s @ %s (metrics: %s)\n",
			f.memoryDuration, f.memoryInterval, metricsURL)
		memCfg := harness.MemoryConfig{
			PID:            pipelockPID,
			Duration:       f.memoryDuration,
			SampleInterval: f.memoryInterval,
			MetricsURL:     metricsURL,
		}
		report.Memory = harness.RunMemory(ctx, memCfg)
	}

	// Tear down the latency pipelock before cold-start so port reuse is clean.
	_ = pipelockProc.Process.Kill()
	_, _ = pipelockProc.Process.Wait()

	// Phase 2: cold-start measurement across all three configs.
	fmt.Fprintf(os.Stderr, "[bench-egress] cold-start: %d iterations across %d configs\n",
		f.coldStartIter, len(configs))
	csCfg := harness.ColdStartConfig{
		PipelockBinary: f.pipelockBinary,
		Configs:        toHarnessSpecs(configs),
		Iterations:     f.coldStartIter,
		StartupTimeout: 10 * time.Second,
	}
	report.ColdStart = harness.RunColdStart(ctx, csCfg)

	// Phase 3: emit JSON.
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeJSON(f.output, report); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[bench-egress] wrote %s\n", f.output)
	return nil
}

// Report is the full benchmark output document.
type Report struct {
	BenchVersion          string                    `json:"bench_version"`
	StartedAt             string                    `json:"started_at"`
	FinishedAt            string                    `json:"finished_at,omitempty"`
	Mode                  string                    `json:"mode"` // "quick" or "release"
	Host                  HostInfo                  `json:"host"`
	Pipelock              PipelockInfo              `json:"pipelock"`
	PipelockListen        string                    `json:"pipelock_listen,omitempty"`
	PipelockMetricsListen string                    `json:"pipelock_metrics_listen,omitempty"`
	LatencyConfigName     string                    `json:"latency_config_name,omitempty"`
	LatencyConfigSHA256   string                    `json:"latency_config_sha256,omitempty"`
	Latency               LatencyResults            `json:"latency"`
	ColdStart             []harness.ColdStartResult `json:"cold_start,omitempty"`
	Memory                harness.MemoryResult      `json:"memory,omitempty"`
}

// LatencyResults groups the per-transport results.
type LatencyResults struct {
	HTTP      harness.TransportResult `json:"http"`
	SSE       harness.TransportResult `json:"sse"`
	Toolchain harness.TransportResult `json:"toolchain"`
	WebSocket harness.TransportResult `json:"websocket"`
	MCPStdio  harness.TransportResult `json:"mcp_stdio"`
}

// HostInfo captures the bench rig so readers can judge how comparable their
// own re-run is.
type HostInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	NumCPU       int    `json:"num_cpu"`
	GOMAXPROCS   int    `json:"gomaxprocs"`
	GoVersion    string `json:"go_version"`
	KernelString string `json:"kernel,omitempty"`
	CPUModel     string `json:"cpu_model,omitempty"`
	CPUGovernor  string `json:"cpu_governor,omitempty"`
	MemTotalKB   uint64 `json:"mem_total_kb,omitempty"`
}

// PipelockInfo captures which pipelock binary the bench measured.
type PipelockInfo struct {
	GitSHA     string `json:"git_sha,omitempty"`
	GitDirty   bool   `json:"git_dirty"`
	Version    string `json:"version,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
}

func newReport(f flags) *Report {
	mode := "quick"
	if f.release {
		mode = "release"
	}
	r := &Report{
		BenchVersion: benchVersion,
		StartedAt:    time.Now().UTC().Format(time.RFC3339),
		Mode:         mode,
		Host: HostInfo{
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			NumCPU:       runtime.NumCPU(),
			GOMAXPROCS:   runtime.GOMAXPROCS(0),
			GoVersion:    runtime.Version(),
			KernelString: readKernel(),
			CPUModel:     readCPUModel(),
			CPUGovernor:  readCPUGovernor(),
			MemTotalKB:   readMemTotalKB(),
		},
		Pipelock: PipelockInfo{
			GitSHA:     readGitSHA(),
			GitDirty:   readGitDirty(),
			Version:    readPipelockVersion(f.pipelockBinary),
			BinaryPath: absOrSelf(f.pipelockBinary),
		},
	}
	return r
}

// startPipelock spawns the binary with the supplied config on a free port and
// blocks until /health returns 200. Returns the chosen listen address, the
// subprocess, and its pid.
func startPipelock(ctx context.Context, binary, configPath string) (string, *exec.Cmd, int, error) {
	port, err := pickFreePort()
	if err != nil {
		return "", nil, 0, err
	}
	listen := "127.0.0.1:" + strconv.Itoa(port)
	// G204: binary + configPath supplied by the bench operator at startup.
	cmd := exec.CommandContext(ctx, binary, "run", "--config", configPath, "--listen", listen) //nolint:gosec
	cmd.Stderr = io.Discard
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return "", nil, 0, err
	}
	// Wait for /health to return 200, up to 10 seconds.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pingHealth(ctx, listen) {
			return listen, cmd, cmd.Process.Pid, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	return "", nil, 0, fmt.Errorf("pipelock did not become ready at %s within 10s", listen)
}

func pingHealth(ctx context.Context, listen string) bool {
	client, err := harness.NewProbeClient()
	if err != nil {
		return false
	}
	return client.Healthy(ctx, "http://"+listen+"/health")
}

func pickFreePort() (int, error) {
	const maxAttempts = 5
	for i := 0; i < maxAttempts; i++ {
		p, err := harness.PickFreePort()
		if err == nil {
			return p, nil
		}
	}
	return 0, fmt.Errorf("could not pick free port after %d attempts", maxAttempts)
}

// configSpec stages a bench config and its content hash for the JSON output.
type configSpec struct {
	Name string
	Path string
	SHA  string
}

func loadConfigSpecs(dir string) ([]configSpec, error) {
	names := []string{"minimal", "default", "full"}
	out := make([]configSpec, 0, len(names))
	for _, n := range names {
		path := filepath.Clean(filepath.Join(dir, n+".yaml"))
		b, err := os.ReadFile(path) //nolint:gosec // path constructed from controlled config-dir + literal name
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		sum := sha256.Sum256(b)
		out = append(out, configSpec{
			Name: n,
			Path: path,
			SHA:  hex.EncodeToString(sum[:]),
		})
	}
	return out, nil
}

func toHarnessSpecs(in []configSpec) []harness.ConfigSpec {
	out := make([]harness.ConfigSpec, 0, len(in))
	for _, s := range in {
		out = append(out, harness.ConfigSpec{Name: s.Name, Path: s.Path})
	}
	return out
}

// materializeRuntimeConfig copies the source YAML to a temp file with
// metrics_listen appended. Returns the temp path and a cleanup func.
//
// Pipelock's `pipelock run` does not expose a --metrics-listen flag, only
// --listen. To wire the metrics endpoint without modifying tracked bench
// configs (which other invocations share), the bench writes a transient
// copy with one extra line. The temp file is removed at the end of the run.
func materializeRuntimeConfig(srcPath, metricsListen string) (string, func(), error) {
	clean := filepath.Clean(srcPath)
	src, err := os.ReadFile(clean) //nolint:gosec // clean of operator-controlled path
	if err != nil {
		return "", func() {}, fmt.Errorf("read source config: %w", err)
	}
	tmp, err := os.CreateTemp("", "pipelock-bench-runtime-*.yaml")
	if err != nil {
		return "", func() {}, fmt.Errorf("temp config: %w", err)
	}
	tmpPath := tmp.Name()
	body := append([]byte{}, src...)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	body = append(body, []byte("\n# Injected by bench-egress runtime config:\nmetrics_listen: \""+metricsListen+"\"\n")...)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", func() {}, fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", func() {}, fmt.Errorf("close temp config: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmpPath) }
	return tmpPath, cleanup, nil
}

// readGitSHA returns the short SHA of HEAD in the current directory, or "".
func readGitSHA() string {
	out, err := runCmd(context.Background(), "git", "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// readGitDirty reports whether the worktree has uncommitted changes.
func readGitDirty() bool {
	out, err := runCmd(context.Background(), "git", "status", "--porcelain")
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(out)) > 0
}

func readPipelockVersion(binary string) string {
	out, err := runCmd(context.Background(), binary, "--version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func readKernel() string {
	out, err := runCmd(context.Background(), "uname", "-sr")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// runCmd is a tiny exec wrapper that satisfies the noctx linter and centralizes
// the "expect short stdout, ignore stderr" pattern used by the host-info probes.
// Each call uses a 2-second deadline so a stuck subprocess can't hang the bench.
func runCmd(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // operator-controlled commands
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func readCPUModel() string {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") {
			if idx := strings.Index(line, ":"); idx != -1 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

func readCPUGovernor() string {
	b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readMemTotalKB() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseUint(fields[1], 10, 64)
				return v
			}
		}
	}
	return 0
}

func absOrSelf(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

func writeJSON(path string, r *Report) error {
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return err
	}
	// G304: path is supplied by the bench operator via --output.
	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
