// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func deferApprovalPolicy(profile config.DeferResolverProfile) *policy.Config {
	const profileName = "approve"
	return &policy.Config{
		Action: config.ActionWarn,
		DeferResolverProfiles: map[string]config.DeferResolverProfile{
			profileName: profile,
		},
		Rules: []*policy.CompiledRule{
			{
				Name:        "hold-send",
				ToolPattern: regexp.MustCompile(`^send_tool$`),
				Action:      config.ActionDefer,
				ResolutionPolicy: config.DeferResolutionPolicy{
					ResolverProfile: profileName,
					AllowOn:         config.DeferAllowOn{Approval: true},
				},
			},
		},
	}
}

func TestExecuteDeferApprovalResolverStrictResults(t *testing.T) {
	held := deferred.HeldAction{
		DeferID:   "d1",
		ActionID:  "d1",
		Target:    "send_tool",
		Method:    methodToolsCall,
		Surface:   deferred.SurfaceMCPStdio,
		Deadline:  time.Now().Add(time.Second),
		ArgDigest: "sha256:abc len=10",
	}
	for _, tt := range []struct {
		name    string
		profile config.DeferResolverProfile
		want    string
		wantErr bool
	}{
		{
			name:    "allow",
			profile: config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}},
			want:    config.ActionAllow,
		},
		{
			name:    "block",
			profile: config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf block"}},
			want:    config.ActionBlock,
		},
		{
			name:    "step up",
			profile: config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf step_up"}},
			want:    config.ActionStepUp,
		},
		{
			name:    "ambiguous output",
			profile: config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf 'allow block'"}},
			wantErr: true,
		},
		{
			name:    "nonzero",
			profile: config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "exit 2"}},
			wantErr: true,
		},
		{
			name:    "spawn error",
			profile: config.DeferResolverProfile{Exec: []string{"/definitely/not/present"}},
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeDeferApprovalResolver(context.Background(), held, "approve", tt.profile, `{"secret":"token"}`, nil, io.Discard)
			if tt.wantErr {
				if err == nil {
					t.Fatal("executeDeferApprovalResolver succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("executeDeferApprovalResolver returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("decision = %q, want %q", got, tt.want)
			}
		})
	}

	expired := held
	expired.Deadline = time.Now().Add(-time.Second)
	if _, err := executeDeferApprovalResolver(context.Background(), expired, "approve", config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}, "{}", nil, io.Discard); err == nil {
		t.Fatal("expired hold resolver succeeded, want error")
	}
	deadline := held
	deadline.Deadline = time.Now().Add(20 * time.Millisecond)
	if _, err := executeDeferApprovalResolver(context.Background(), deadline, "approve", config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "sleep 1; printf allow"}}, "{}", nil, io.Discard); err == nil {
		t.Fatal("slow resolver succeeded, want deadline error")
	}
	noisy := held
	noisy.Deadline = time.Now().Add(time.Second)
	if _, err := executeDeferApprovalResolver(context.Background(), noisy, "approve", config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "yes allow | head -c 8192"}}, "{}", nil, io.Discard); err == nil {
		t.Fatal("oversized resolver output succeeded, want error")
	}
	integrityBlocked := held
	integrityBlocked.Deadline = time.Now().Add(time.Second)
	if _, err := executeDeferApprovalResolver(context.Background(), integrityBlocked, "approve", config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}, "{}", &config.MCPBinaryIntegrity{
		Enabled:      true,
		ManifestPath: filepath.Join(t.TempDir(), "missing-manifest.json"),
		Action:       config.ActionBlock,
	}, io.Discard); err == nil {
		t.Fatal("resolver bypassed blocking binary integrity failure")
	}
}

func TestFinalizeDeferApprovalResolver_CanceledContextBlocksCleanExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr cappedOutputBuffer
	stdout.limit = maxDeferResolverOutputBytes
	if _, err := stdout.Write([]byte(config.ActionAllow)); err != nil {
		t.Fatalf("writing resolver output: %v", err)
	}

	got, err := finalizeDeferApprovalResolver(ctx, nil, &stdout, &stderr)
	if got != config.ActionBlock {
		t.Errorf("decision = %q, want %q after cancellation", got, config.ActionBlock)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context cancellation", err)
	}
}

func TestForwardScannedInput_DeferResolverAllowsAndMinimizesManifest(t *testing.T) {
	sc := testInputScanner(t)
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	profile := config.DeferResolverProfile{
		Exec: []string{"/bin/sh", "-c", "printf '%s' \"$__PIPELOCK_DEFER_RESOLVER_MANIFEST\" > " + manifestPath + "; printf allow"},
	}
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
	emitter, _, _, _ := newReceiptTestHarness(t)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"super-secret-token"}}}` + "\n"

	inputR, inputW := io.Pipe()
	defer func() { _ = inputW.Close() }()
	var serverBuf, logBuf syncBuffer
	blockedCh := make(chan BlockedRequest, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(
			transport.NewStdioReader(inputR),
			transport.NewStdioWriter(&serverBuf),
			&logBuf,
			config.ActionWarn,
			config.ActionBlock,
			blockedCh,
			nil,
			nil,
			MCPProxyOpts{
				Scanner:        sc,
				Transport:      deferred.SurfaceMCPStdio,
				PolicyCfg:      deferApprovalPolicy(profile),
				DeferManager:   manager,
				ReceiptEmitter: emitter,
			},
		)
	}()
	if _, err := inputW.Write([]byte(msg)); err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, time.Second, func() bool {
		return strings.Contains(serverBuf.String(), "send_tool")
	}, "deferred stdio call to be forwarded; log=%s", &logBuf)
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	<-done
	for blocked := range blockedCh {
		t.Fatalf("unexpected block after resolver allow: %+v", blocked)
	}
	manifestBytes, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifest := string(manifestBytes)
	if strings.Contains(manifest, "super-secret-token") {
		t.Fatalf("resolver manifest leaked raw arguments: %s", manifest)
	}
	if !strings.Contains(manifest, `"arg_digest"`) {
		t.Fatalf("resolver manifest missing arg_digest: %s", manifest)
	}
}

func TestForwardScannedInput_DeferResolverRechecksAuthorityBeforeUpstream(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
	emitter, receiptRecorder, receiptDir, _ := newReceiptTestHarness(t)
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{},"_meta":{"com.pipelock/authority":"grant"}}}` + "\n"

	inputR, inputW := io.Pipe()
	defer func() { _ = inputW.Close() }()
	var serverBuf, logBuf syncBuffer
	blockedCh := make(chan BlockedRequest, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(
			transport.NewStdioReader(inputR),
			transport.NewStdioWriter(&serverBuf),
			&logBuf,
			config.ActionWarn,
			config.ActionBlock,
			blockedCh,
			nil,
			nil,
			MCPProxyOpts{
				Scanner:        sc,
				Transport:      deferred.SurfaceMCPStdio,
				PolicyCfg:      deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}),
				DeferManager:   manager,
				ReceiptEmitter: emitter,
				AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
					return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
				}),
				AuthorityActor:       "agent-a",
				AuthorityDestination: "server-a",
			},
		)
	}()
	if _, err := inputW.Write([]byte(msg)); err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, time.Second, func() bool {
		select {
		case blocked := <-blockedCh:
			return blocked.ErrorCode == -32008
		default:
			return false
		}
	}, "deferred stdio authority denial; log=%s", &logBuf)
	if serverBuf.String() != "" {
		t.Fatalf("authority-denied deferred call reached upstream: %s", serverBuf.String())
	}
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	<-done
	if err := receiptRecorder.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	assertSingleDeferredAuthorityBlockReceipt(t, receiptsByVerdict(readActionReceipts(t, receiptDir), config.ActionBlock))
}

func TestRunHTTPProxy_DeferResolverAllowsBridge(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
	emitter, _, _, _ := newReceiptTestHarness(t)
	upstreamBody := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inputR, inputW := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, inputR, &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
			Scanner:        sc,
			PolicyCfg:      deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}),
			DeferManager:   manager,
			ReceiptEmitter: emitter,
		})
	}()
	_, err := inputW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"bridge-secret"}}}` + "\n"))
	if err != nil {
		t.Fatalf("write input: %v", err)
	}
	select {
	case body := <-upstreamBody:
		if !strings.Contains(body, "send_tool") {
			t.Fatalf("upstream body = %s, want held call", body)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for bridge forward; stderr=%s stdout=%s", &stderr, &stdout)
	}
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	cancel()
	if err := <-done; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("RunHTTPProxy returned error: %v", err)
	}
}

func TestRunHTTPProxy_DeferResolverRechecksAuthorityBeforeUpstream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow bool
	}{
		{name: "allow", allow: true},
		{name: "deny", allow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := testInputScanner(t)
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
			emitter, receiptRecorder, receiptDir, _ := newReceiptTestHarness(t)
			var upstreamCalls, verifierCalls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			}))
			defer upstream.Close()

			ctx, cancel := context.WithCancel(context.Background())
			inputR, inputW := io.Pipe()
			var stdout, stderr syncBuffer
			done := make(chan error, 1)
			go func() {
				done <- RunHTTPProxy(ctx, inputR, &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
					Scanner:              sc,
					PolicyCfg:            deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}),
					DeferManager:         manager,
					ReceiptEmitter:       emitter,
					AuthorityActor:       "agent-a",
					AuthorityDestination: upstream.URL,
					AuthorityVerifier: authorityVerifierFunc(func(context.Context, authority.Request) authority.Result {
						verifierCalls.Add(1)
						if tc.allow {
							return authority.Result{Decision: authority.DecisionAllow, Reason: authority.ReasonMatched}
						}
						return authority.Result{Decision: authority.DecisionDeny, Reason: authority.ReasonActionMismatch}
					}),
				})
			}()
			msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{},"_meta":{"com.pipelock/authority":"grant"}}}` + "\n"
			if _, err := inputW.Write([]byte(msg)); err != nil {
				t.Fatalf("write input: %v", err)
			}
			if tc.allow {
				testwait.For(t, time.Second, func() bool { return upstreamCalls.Load() == 1 }, "deferred allowed call to reach upstream; stderr=%s stdout=%s", &stderr, &stdout)
			} else {
				testwait.For(t, time.Second, func() bool { return strings.Contains(stdout.String(), `"code":-32008`) }, "authority denial response; stderr=%s stdout=%s", &stderr, &stdout)
				if upstreamCalls.Load() != 0 {
					t.Fatalf("authority-denied deferred call reached upstream %d times", upstreamCalls.Load())
				}
			}
			if verifierCalls.Load() != 1 {
				t.Fatalf("verifier calls = %d, want 1", verifierCalls.Load())
			}
			if err := inputW.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			cancel()
			if err := <-done; err != nil && !strings.Contains(err.Error(), "context canceled") {
				t.Fatalf("RunHTTPProxy returned error: %v", err)
			}
			if err := receiptRecorder.Close(); err != nil {
				t.Fatalf("recorder.Close: %v", err)
			}
			if !tc.allow {
				assertSingleDeferredAuthorityBlockReceipt(t, receiptsByVerdict(readActionReceipts(t, receiptDir), config.ActionBlock))
			}
		})
	}
}

func TestRunHTTPProxy_DeferResolverBlocksBridge(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
	emitter, _, _, _ := newReceiptTestHarness(t)
	upstreamHit := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inputR, inputW := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, inputR, &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
			Scanner:        sc,
			PolicyCfg:      deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf block"}}),
			DeferManager:   manager,
			ReceiptEmitter: emitter,
		})
	}()
	_, err := inputW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"bridge-secret"}}}` + "\n"))
	if err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, time.Second, func() bool {
		return strings.Contains(stdout.String(), "deferred action denied")
	}, "deferred HTTP call to be denied; stderr=%s stdout=%s", &stderr, &stdout)
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	cancel()
	if err := <-done; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("RunHTTPProxy returned error: %v", err)
	}
	select {
	case <-upstreamHit:
		t.Fatal("blocked deferred call reached upstream")
	default:
	}
}

func TestRunHTTPProxy_DeferCapacityBlocksBridge(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Hour, MaxPending: 1, MaxPendingPerSession: 1, MaxPendingBytes: 4096})
	sessionID := captureSessionID(deferred.SurfaceMCPHTTPUpstream)
	if err := manager.Hold(deferred.HeldAction{
		DeferID:   "occupied",
		ActionID:  "occupied",
		Target:    "send_tool",
		SizeBytes: 1,
		Authority: deferred.AuthoritySnapshot{
			SessionID:         sessionID,
			SessionIDOriginal: sessionID,
		},
		Resolve: func(deferred.Resolution) {},
	}); err != nil {
		t.Fatalf("preload Hold: %v", err)
	}
	emitter, _, _, _ := newReceiptTestHarness(t)
	upstreamHit := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inputR, inputW := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- RunHTTPProxy(ctx, inputR, &stdout, &stderr, upstream.URL, nil, MCPProxyOpts{
			Scanner:        sc,
			PolicyCfg:      deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}),
			DeferManager:   manager,
			ReceiptEmitter: emitter,
		})
	}()
	_, err := inputW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"bridge-secret"}}}` + "\n"))
	if err != nil {
		t.Fatalf("write input: %v", err)
	}
	testwait.For(t, time.Second, func() bool {
		return strings.Contains(stdout.String(), "defer capacity exceeded")
	}, "deferred HTTP call to fail capacity; stderr=%s stdout=%s", &stderr, &stdout)
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	cancel()
	if err := <-done; err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("RunHTTPProxy returned error: %v", err)
	}
	select {
	case <-upstreamHit:
		t.Fatal("capacity-blocked deferred call reached upstream")
	default:
	}
}

func TestForwardScannedInput_DeferCapacityBlocks(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Hour, MaxPending: 1, MaxPendingPerSession: 1, MaxPendingBytes: 4096})
	sessionID := captureSessionID(deferred.SurfaceMCPStdio)
	if err := manager.Hold(deferred.HeldAction{
		DeferID:   "occupied",
		ActionID:  "occupied",
		Target:    "send_tool",
		SizeBytes: 1,
		Authority: deferred.AuthoritySnapshot{
			SessionID:         sessionID,
			SessionIDOriginal: sessionID,
		},
		Resolve: func(deferred.Resolution) {},
	}); err != nil {
		t.Fatalf("preload Hold: %v", err)
	}
	emitter, _, _, _ := newReceiptTestHarness(t)
	inputR, inputW := io.Pipe()
	defer func() { _ = inputW.Close() }()
	var serverBuf, logBuf syncBuffer
	blockedCh := make(chan BlockedRequest, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardScannedInput(
			transport.NewStdioReader(inputR),
			transport.NewStdioWriter(&serverBuf),
			&logBuf,
			config.ActionWarn,
			config.ActionBlock,
			blockedCh,
			nil,
			nil,
			MCPProxyOpts{
				Scanner:        sc,
				Transport:      deferred.SurfaceMCPStdio,
				PolicyCfg:      deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}),
				DeferManager:   manager,
				ReceiptEmitter: emitter,
			},
		)
	}()
	if _, err := inputW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"secret"}}}` + "\n")); err != nil {
		t.Fatalf("write input: %v", err)
	}
	select {
	case blocked := <-blockedCh:
		if !strings.Contains(blocked.ErrorMessage, "defer capacity exceeded") {
			t.Fatalf("blocked = %+v, want defer capacity exceeded", blocked)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for capacity block; log=%s", &logBuf)
	}
	if strings.Contains(serverBuf.String(), "send_tool") {
		t.Fatalf("capacity-blocked stdio call was forwarded: %s", &serverBuf)
	}
	if err := inputW.Close(); err != nil {
		t.Fatalf("close input: %v", err)
	}
	<-done
}

func TestForwardScanned_ToolInventoryResolvesHeldActions(t *testing.T) {
	sc := testInputScanner(t)
	for _, tt := range []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "confirm allows",
			response: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"safe"}]}}` + "\n",
			want:     config.ActionAllow,
		},
		{
			name:     "new tool blocks",
			response: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"safe"},{"name":"exec_command","description":"safe"}]}}` + "\n",
			want:     config.ActionBlock,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			baseline := tools.NewToolBaseline()
			requireKnownTools(t, baseline, []string{"read_file"})
			toolCfg := &tools.ToolScanConfig{Action: config.ActionBlock, DetectDrift: true, Baseline: baseline}
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
			resolved := make(chan deferred.Resolution, 1)
			sessionID := captureSessionID(deferred.SurfaceMCPStdio)
			if err := manager.Hold(deferred.HeldAction{
				DeferID:   "d1",
				ActionID:  "d1",
				Target:    "send_tool",
				Surface:   deferred.SurfaceMCPStdio,
				SizeBytes: 1,
				RulePolicy: config.DeferResolutionPolicy{
					AllowOn: config.DeferAllowOn{ToolInventoryBaseline: true},
				},
				Authority: deferred.AuthoritySnapshot{SessionID: sessionID, SessionIDOriginal: sessionID},
				Resolve:   func(res deferred.Resolution) { resolved <- res },
			}); err != nil {
				t.Fatalf("Hold: %v", err)
			}
			var out, logBuf syncBuffer
			_, err := ForwardScanned(
				transport.NewStdioReader(strings.NewReader(tt.response)),
				transport.NewStdioWriter(&out),
				&logBuf,
				nil,
				MCPProxyOpts{Scanner: sc, ToolCfg: toolCfg, DeferManager: manager, Transport: deferred.SurfaceMCPStdio},
			)
			if err != nil {
				t.Fatalf("ForwardScanned: %v", err)
			}
			select {
			case got := <-resolved:
				if got.FinalDecision != tt.want || got.ResolutionSource != deferred.SourceToolInventory {
					t.Fatalf("resolution = (%q,%q), want (%q,%q)", got.FinalDecision, got.ResolutionSource, tt.want, deferred.SourceToolInventory)
				}
			case <-time.After(time.Second):
				t.Fatal("inventory did not resolve held action")
			}
		})
	}
}

func TestForwardScannedInput_DeferResolverShutdownDoesNotPanic(t *testing.T) {
	sc := testInputScanner(t)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Second, MaxPending: 4, MaxPendingPerSession: 4, MaxPendingBytes: 4096})
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tool","arguments":{"token":"super-secret-token"}}}` + "\n"

	for i := 0; i < 25; i++ {
		inputR, inputW := io.Pipe()
		var serverBuf, logBuf syncBuffer
		blockedCh := make(chan BlockedRequest, 4)
		done := make(chan struct{})
		go func() {
			defer close(done)
			ForwardScannedInput(
				transport.NewStdioReader(inputR),
				transport.NewStdioWriter(&serverBuf),
				&logBuf,
				config.ActionWarn,
				config.ActionBlock,
				blockedCh,
				nil,
				nil,
				MCPProxyOpts{
					Scanner:      sc,
					Transport:    deferred.SurfaceMCPStdio,
					PolicyCfg:    deferApprovalPolicy(config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "sleep 0.01; printf allow"}}),
					DeferManager: manager,
				},
			)
		}()
		if _, err := inputW.Write([]byte(msg)); err != nil {
			t.Fatalf("write input: %v", err)
		}
		if err := inputW.Close(); err != nil {
			t.Fatalf("close input: %v", err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("ForwardScannedInput did not shut down; log=%s server=%s", &logBuf, &serverBuf)
		}
		for range blockedCh {
		}
	}
}

func assertSingleDeferredAuthorityBlockReceipt(t *testing.T, receipts []receipt.Receipt) {
	t.Helper()
	if len(receipts) != 1 {
		t.Fatalf("receipt count = %d, want exactly one deferred authority denial", len(receipts))
	}
	record := receipts[0].ActionRecord
	assertAuthorityBlockReceiptRecord(t, record)
	if record.ResolutionSource != deferred.SourceAuthority {
		t.Fatalf("resolution_source = %q, want %q", record.ResolutionSource, deferred.SourceAuthority)
	}
	if record.DecisionPhase != receipt.DecisionPhaseResolution {
		t.Fatalf("decision_phase = %q, want %q", record.DecisionPhase, receipt.DecisionPhaseResolution)
	}
}
