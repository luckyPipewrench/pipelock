// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHardeningLiveRunRejectsMalformedConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := liveRunProxyConfig(LiveRunOpts{ModelBaseURL: "file:///tmp/model"}); err == nil {
		t.Fatal("liveRunProxyConfig accepted a non-HTTP model URL")
	}

	missingKey := filepath.Join(t.TempDir(), "missing-orchestrator.key")
	if _, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID:          LiveDemoScenarioID,
		RunNonce:            "bad-key",
		OrchestratorKeyPath: missingKey,
	}); err == nil || !strings.Contains(err.Error(), "load orchestrator key") {
		t.Fatalf("StartLiveRun missing key error = %v", err)
	}

	if _, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID: "does-not-exist",
		RunNonce:   "bad-scenario",
	}); err == nil || !strings.Contains(err.Error(), "unknown scenario") {
		t.Fatalf("StartLiveRun unknown scenario error = %v", err)
	}
}

func TestHardeningLiveRunProbeCancellationStopsProcess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(*LiveRun) error
	}{
		{
			name: "egress",
			run: func(lr *LiveRun) error {
				_, err := lr.runEgressProbe([]string{"127.0.0.1:1"}, false)
				return err
			},
		},
		{
			name: "local escape",
			run: func(lr *LiveRun) error {
				_, err := lr.runLocalEscapeProbe(false)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			script := filepath.Join(t.TempDir(), "probe")
			body := "#!/bin/sh\n: > \"" + marker + "\"\nexec sleep 30\n"
			if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- executable test fixture.
				t.Fatalf("write probe: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lr := &LiveRun{ctx: ctx, agentBin: script}
			result := make(chan error, 1)
			go func() {
				result <- tc.run(lr)
			}()

			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			startDeadline := time.NewTimer(2 * time.Second)
			defer startDeadline.Stop()
		waitForStart:
			for {
				select {
				case <-ticker.C:
					if _, err := os.Stat(marker); err == nil {
						break waitForStart
					} else if !os.IsNotExist(err) {
						t.Fatalf("stat start marker: %v", err)
					}
				case err := <-result:
					t.Fatalf("probe exited before cancellation: %v", err)
				case <-startDeadline.C:
					t.Fatal("probe process did not start")
				}
			}

			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("probe error = %v, want context cancellation", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("probe process did not terminate after cancellation")
			}
		})
	}
}

func TestHardeningLiveRunFailsClosedOnMissingEvidenceAndUnsupportedStep(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen := func() net.Listener {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return ln
	}

	lr := &LiveRun{
		ctx:         ctx,
		cancel:      cancel,
		safeLn:      listen(),
		collectorLn: listen(),
		proxyLn:     listen(),
		evidenceDir: t.TempDir(),
	}
	if err := lr.RunSteps(3); err == nil || !strings.Contains(err.Error(), "unsupported mediated step") {
		t.Fatalf("RunSteps error = %v", err)
	}
	if got := lr.Verdicts(); got != nil {
		t.Fatalf("Verdicts without evidence = %v, want nil", got)
	}
	if lr.HasReceipt("allow") {
		t.Fatal("HasReceipt reported a verdict without evidence")
	}

	if _, err := singleLiveEvidenceFile("["); err == nil {
		t.Fatal("singleLiveEvidenceFile accepted an invalid glob path")
	}
}

func TestHardeningHostWitnessProbeErrorsFailClosed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lr := &LiveRun{
		ctx:    ctx,
		cancel: cancel,
		opts:   LiveRunOpts{RunNonce: "probe-errors"},
		egressProbe: func(_ []string, _ bool) ([]ProbeResult, error) {
			return nil, errors.New("probe unavailable")
		},
	}
	if _, err := lr.buildHostContainmentWitness(ctx); err == nil ||
		!strings.Contains(err.Error(), "operator control probe") {
		t.Fatalf("buildHostContainmentWitness error = %v", err)
	}

	lr.egressProbe = func(targets []string, asAgent bool) ([]ProbeResult, error) {
		if !asAgent {
			return []ProbeResult{{Target: targets[0], Open: true}}, nil
		}
		return nil, errors.New("agent probe unavailable")
	}
	proxyLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listener: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })
	lr.proxyLn = proxyLn
	if _, err := lr.buildHostContainmentWitness(ctx); err == nil ||
		!strings.Contains(err.Error(), "contained agent probe: agent probe unavailable") {
		t.Fatalf("buildHostContainmentWitness agent probe error = %v", err)
	}
}
