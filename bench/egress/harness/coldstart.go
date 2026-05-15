package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ColdStartConfig parameterizes the cold-start measurement.
type ColdStartConfig struct {
	PipelockBinary string        // path to pipelock binary
	Configs        []ConfigSpec  // ordered minimal/default/full
	Iterations     int           // restarts per config
	StartupTimeout time.Duration // give up if pipelock doesn't become ready
}

// ConfigSpec names a pipelock config for the cold-start measurement.
type ConfigSpec struct {
	Name string // "minimal" / "default" / "full"
	Path string // path to YAML
}

// ColdStartResult holds the three readiness measurements for one config.
type ColdStartResult struct {
	Config         string `json:"config"`
	ProcessStarted Stats  `json:"process_started"`
	HealthReady    Stats  `json:"health_ready"`
	FirstRequest   Stats  `json:"first_request_served"`
	Error          string `json:"error,omitempty"`
}

// RunColdStart spawns pipelock Iterations times per config and records three
// readiness signals: process exec succeeded, /health returns 200, first
// proxied HTTP request succeeded. The headline number is FirstRequest.
func RunColdStart(ctx context.Context, cfg ColdStartConfig) []ColdStartResult {
	out := make([]ColdStartResult, 0, len(cfg.Configs))
	for _, spec := range cfg.Configs {
		res := ColdStartResult{Config: spec.Name}
		var procSamples, healthSamples, firstReqSamples []time.Duration
		for i := 0; i < cfg.Iterations; i++ {
			if ctx.Err() != nil {
				break
			}
			proc, health, first, err := oneColdStart(ctx, cfg.PipelockBinary, spec.Path, cfg.StartupTimeout)
			if err != nil {
				res.Error = err.Error()
				break
			}
			procSamples = append(procSamples, proc)
			healthSamples = append(healthSamples, health)
			firstReqSamples = append(firstReqSamples, first)
		}
		res.ProcessStarted = Summarize(procSamples)
		res.HealthReady = Summarize(healthSamples)
		res.FirstRequest = Summarize(firstReqSamples)
		out = append(out, res)
	}
	return out
}

// oneColdStart runs a single cold-start iteration. The pipelock subprocess is
// killed after measurements complete.
func oneColdStart(ctx context.Context, binary, configPath string, timeout time.Duration) (proc, health, first time.Duration, err error) {
	port, err := pickFreePort()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("pick port: %w", err)
	}
	listen := "127.0.0.1:" + strconv.Itoa(port)
	procCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	// G204: binary + configPath are supplied by the bench operator at startup.
	cmd := exec.CommandContext(procCtx, binary, "run", "--config", configPath, "--listen", listen) //nolint:gosec
	// Suppress pipelock's stderr to keep the bench output clean. If diagnosis
	// is ever needed, /tmp/pipelock-coldstart.stderr would be a good target.
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		return 0, 0, 0, fmt.Errorf("start: %w", err)
	}
	proc = time.Since(start)
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	healthURL := "http://" + listen + "/health"
	healthCh := pollUntil200(procCtx, healthURL, 50*time.Millisecond)
	select {
	case <-procCtx.Done():
		return proc, 0, 0, fmt.Errorf("health: %w", procCtx.Err())
	case <-healthCh:
	}
	health = time.Since(start)

	// First successful proxied request: bench client → pipelock fetch proxy
	// pointed at a tiny mock we spin up locally.
	mock, mockAddr, err := httpEchoForColdStart(procCtx)
	if err != nil {
		return proc, health, 0, fmt.Errorf("mock: %w", err)
	}
	defer func() { _ = mock.Close() }()
	client, err := newHTTPClient(LatencyConfig{HTTPTimeout: 5 * time.Second}, "http://"+listen)
	if err != nil {
		return proc, health, 0, fmt.Errorf("client: %w", err)
	}
	for {
		if procCtx.Err() != nil {
			return proc, health, 0, procCtx.Err()
		}
		_, err := timeHTTPGet(procCtx, client, "http://"+mockAddr+"/")
		if err == nil {
			break
		}
	}
	first = time.Since(start)
	return proc, health, first, nil
}

// pollUntil200 hits url at the given interval until it returns 200. The
// returned channel closes on success or when ctx is canceled.
func pollUntil200(ctx context.Context, url string, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		client := &http.Client{Timeout: 250 * time.Millisecond}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
				resp, err := client.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					_ = resp.Body.Close()
					return
				}
				if resp != nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()
	return done
}

// pickFreePort returns a random free TCP port on 127.0.0.1. The port is closed
// before returning; race with another process is possible but vanishingly
// rare for a bench loop.
func pickFreePort() (int, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

// httpEchoForColdStart starts a tiny HTTP responder used as the upstream for
// the cold-start first-request measurement. Imported via the httpecho mock to
// avoid duplicating the canned-body server.
func httpEchoForColdStart(ctx context.Context) (closer, string, error) {
	// Delegate to the httpecho mock package by importing it. We cannot import
	// here without creating a cycle, so inline a tiny variant.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return &shutdownCloser{srv: srv}, ln.Addr().String(), nil
}

type closer interface {
	Close() error
}

type shutdownCloser struct {
	srv *http.Server
}

func (s *shutdownCloser) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// suppressStderrIfQuiet is reserved for future use if we add a --quiet flag
// that hides pipelock stderr. For now stderr is dropped via cmd.Stderr = nil.
//
//nolint:unused // referenced from comment for future maintainers
var suppressStderrIfQuiet = func(_ *os.File) {}
