// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestNewServer_FlightRecorderRetentionRunsAtStartup(t *testing.T) {
	dir := t.TempDir()
	oldJSONL := writeRetentionTestFile(t, dir, "evidence-proxy-0.jsonl", 48*time.Hour)
	oldKept := writeRetentionTestFile(t, dir, "evidence-proxy-1.jsonl", 48*time.Hour)
	oldRemoved := writeRetentionTestFile(t, dir, "evidence-proxy-2.raw.enc", 48*time.Hour)
	recent := writeRetentionTestFile(t, dir, "evidence-proxy-3.raw.enc", time.Hour)
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(dir),
		"  retention_days: 1",
		"  sign_checkpoints: false",
		"",
	}, "\n"))

	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: buf, Stderr: buf})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	if _, err := os.Stat(oldRemoved); !os.IsNotExist(err) {
		t.Fatalf("old raw escrow file stat = %v, want not exist", err)
	}
	for _, path := range []string{oldJSONL, oldKept, recent} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retained file %s stat: %v", filepath.Base(path), err)
		}
	}
	if !buf.contains("recorder retention expired 1 old raw escrow sidecar") {
		t.Fatalf("startup output missing retention expiry note:\n%s", buf.String())
	}
}

func TestNewServer_FlightRecorderRetentionDisabledKeepsOldFiles(t *testing.T) {
	dir := t.TempDir()
	oldFile := writeRetentionTestFile(t, dir, "evidence-proxy-0.jsonl", 48*time.Hour)
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(dir),
		"  retention_days: 0",
		"  sign_checkpoints: false",
		"",
	}, "\n"))

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	if _, err := os.Stat(oldFile); err != nil {
		t.Fatalf("retention_days=0 should keep old evidence file: %v", err)
	}
}

func TestFlightRecorderRetentionPeriodicTickExpiresOldFiles(t *testing.T) {
	dir := t.TempDir()
	oldJSONL := writeRetentionTestFile(t, dir, "evidence-proxy-0.jsonl", 48*time.Hour)
	oldKept := writeRetentionTestFile(t, dir, "evidence-proxy-1.jsonl", 48*time.Hour)
	oldRemoved := writeRetentionTestFile(t, dir, "evidence-proxy-2.raw.enc", 48*time.Hour)
	rec, err := recorder.New(recorder.Config{
		Enabled:       true,
		Dir:           dir,
		RetentionDays: 1,
	}, nil, nil)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	defer func() { _ = rec.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	startFlightRecorderRetention(ctx, &wg, rec, &syncBuffer{}, time.Millisecond, nil)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	testwait.For(t, 2*time.Second, func() bool {
		_, err := os.Stat(oldRemoved)
		return os.IsNotExist(err)
	}, "periodic retention expiry to remove old raw escrow sidecar")
	if _, err := os.Stat(oldKept); err != nil {
		t.Fatalf("periodic retention removed newest session shard: %v", err)
	}
	if _, err := os.Stat(oldJSONL); err != nil {
		t.Fatalf("periodic retention removed JSONL chain shard: %v", err)
	}
}

func TestFlightRecorderRetentionFailureDoesNotBlockStartupOrHealth(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  dir: " + strconv.Quote(dir),
		"  retention_days: 1",
		"  sign_checkpoints: false",
		"",
	}, "\n"))

	failingExpire := func(_ *recorder.Recorder) (int, error) {
		return 0, errors.New("forced retention failure")
	}
	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        cfgPath,
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            buf,
		Stderr:                            buf,
		allowEphemeralListenersForTesting: true,
		expireForTesting:                  failingExpire,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Fatal("server did not stop after cancellation")
		}
	})

	testwait.For(t, 2*time.Second, func() bool {
		return buf.contains("Health: http://")
	}, "server startup banner")
	healthURL := startupLineURL(t, buf.String(), "Health:")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil) // #nosec G107 -- test server URL from local ephemeral listener
	if err != nil {
		t.Fatalf("new request %s: %v", healthURL, err)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", healthURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	if !buf.contains("recorder retention expiry failed") {
		t.Fatalf("startup output missing retention failure warning:\n%s", buf.String())
	}
}

func writeRetentionTestFile(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	ts := time.Now().Add(-age)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return path
}

func startupLineURL(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("missing %s line in output:\n%s", prefix, output)
	return ""
}

func TestFlightRecorderRetentionStartNilInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFlightRecorderRetention(ctx, nil, nil, nil, time.Millisecond, nil)
	var wg sync.WaitGroup
	startFlightRecorderRetention(ctx, &wg, nil, nil, time.Millisecond, nil)
	cancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nil retention runner left goroutine running")
	}
}

// TestFlightRecorderRetentionGuards covers the defensive paths on the retention
// helpers. Retention is best-effort maintenance: a nil recorder, a missing
// waitgroup, or an unreadable evidence directory must degrade quietly rather
// than panic or take the runtime down, since none of them are security signals.
func TestFlightRecorderRetentionGuards(t *testing.T) {
	t.Parallel()

	t.Run("expiry_with_nil_recorder_is_a_noop", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		runFlightRecorderExpiryOnce(nil, &buf, nil)
		if buf.Len() != 0 {
			t.Fatalf("nil recorder produced output %q", buf.String())
		}
	})

	t.Run("start_with_nil_waitgroup_or_recorder_returns", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var wg sync.WaitGroup
		startFlightRecorderRetention(ctx, nil, nil, io.Discard, time.Second, nil)
		startFlightRecorderRetention(ctx, &wg, nil, io.Discard, time.Second, nil)
		// Nothing was scheduled, so Wait must return immediately.
		wg.Wait()
	})

	t.Run("non_positive_interval_falls_back_to_default", func(t *testing.T) {
		t.Parallel()
		// A zero interval must not construct a zero-duration ticker, which
		// panics. Guarding here keeps a misconfigured interval from crashing
		// the runtime at startup.
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		rec, err := recorder.New(recorder.Config{
			Enabled:       true,
			Dir:           t.TempDir(),
			RetentionDays: 1,
		}, nil, nil)
		if err != nil {
			t.Fatalf("recorder.New: %v", err)
		}
		defer func() { _ = rec.Close() }()
		startFlightRecorderRetention(ctx, &wg, rec, io.Discard, 0, nil)
		cancel()
		wg.Wait()
	})

	t.Run("warning_reports_unmeasurable_directory", func(t *testing.T) {
		t.Parallel()
		// Point at a regular file so the directory scan fails. The operator
		// gets an explicit "unavailable" note instead of a silent all-clear.
		f := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := flightRecorderEvidenceWarning(f, 30)
		if !strings.Contains(got, "unavailable") {
			t.Fatalf("warning = %q, want unavailable note", got)
		}
	})
}

// TestFlightRecorderEvidenceWarningNearAndOverLimit covers the operator-facing
// warning text. This is the message that gives an operator a chance to act
// before receipts stop verifying, so both the near-cap and past-cap wordings
// must name the session and the counts rather than warn generically.
func TestFlightRecorderEvidenceWarningNearAndOverLimit(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		files int
		want  []string
	}{
		{
			name:  "below_threshold_is_silent",
			files: 3,
		},
		{
			name:  "near_limit_warns",
			files: recorder.EvidenceFileWarningThreshold,
			want:  []string{"proxy", "near", "warning threshold"},
		},
		{
			name:  "over_limit_says_over",
			files: recorder.MaxEvidenceReadDirectoryEntries + 1,
			want:  []string{"proxy", "over", "bounded resume cap"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for i := range tt.files {
				path := filepath.Join(dir, "evidence-proxy-"+strconv.Itoa(i)+".jsonl")
				if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
					t.Fatalf("write shard %d: %v", i, err)
				}
			}
			got := flightRecorderEvidenceWarning(dir, 30)
			if len(tt.want) == 0 {
				if got != "" {
					t.Fatalf("warning = %q, want empty below threshold", got)
				}
				return
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Fatalf("warning = %q, want substring %q", got, w)
				}
			}
		})
	}
}
