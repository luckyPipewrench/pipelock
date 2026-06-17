// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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
			want:    "step_up",
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
			baseline.SetKnownTools([]string{"read_file"})
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
