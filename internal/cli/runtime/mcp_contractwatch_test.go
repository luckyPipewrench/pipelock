// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const contractWatchWait = 10 * time.Second

func newMCPWatchLoader(t *testing.T) (*contractruntime.Loader, contractruntimetest.Fixture, string) {
	t.Helper()
	fixture := contractruntimetest.NewFixture(t)
	storeDir := t.TempDir()
	env := contractruntimetest.Env()
	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation: 1, PriorHash: "sha256:genesis", Environment: env,
	})
	loader, err := contractruntime.NewLoader(contractruntime.LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.RosterPath(),
		PinnedRootFingerprint: fixture.RootFingerprint(),
		Environment:           env,
		MinSignatures:         1,
		Mode:                  contractruntime.ModeLive,
	}, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return loader, fixture, storeDir
}

func TestStartMCPContractWatch_NilLoaderIsNoop(t *testing.T) {
	stop := startMCPContractWatch(context.Background(), nil, nil)
	if stop == nil {
		t.Fatal("stop must never be nil")
	}
	stop()
}

func TestStartMCPContractWatch_PromotionAppliesWithoutRestart(t *testing.T) {
	loader, fixture, storeDir := newMCPWatchLoader(t)
	stop := startMCPContractWatch(context.Background(), loader, nil)
	t.Cleanup(stop)

	contractruntimetest.WriteSignedActiveStore(t, fixture, storeDir, contractruntimetest.ActiveStoreOptions{
		Generation: 2, PriorHash: loader.Current().ManifestHash(), Environment: contractruntimetest.Env(),
	})
	testwait.For(t, contractWatchWait, func() bool {
		s := loader.Current()
		return s != nil && s.Generation() == 2
	}, "promoted generation to apply without restart")
}

func TestStartMCPContractWatch_CorruptManifestKeepsContractAndIsLogged(t *testing.T) {
	loader, _, storeDir := newMCPWatchLoader(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	good := loader.Current()
	stop := startMCPContractWatch(context.Background(), loader, logger)

	if err := os.WriteFile(filepath.Join(storeDir, "active.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}
	testwait.For(t, contractWatchWait, func() bool {
		data, readErr := os.ReadFile(filepath.Clean(logPath))
		return readErr == nil && strings.Contains(string(data), "CONTRACT_WATCH")
	}, "rejected manifest to be logged")
	if loader.Current() != good {
		t.Fatal("corrupt manifest dropped the last accepted contract")
	}
	stop()
	logger.Close()
}

func TestStartMCPContractWatch_WatcherStartFailureIsLoggedNotSwallowed(t *testing.T) {
	loader, _, storeDir := newMCPWatchLoader(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	good := loader.Current()
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	stop := startMCPContractWatch(context.Background(), loader, logger)
	stop()
	logger.Close()
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "active manifest watcher not running") {
		t.Fatalf("watch failure not logged: %q", data)
	}
	if loader.Current() != good {
		t.Fatal("watch failure dropped the contract")
	}
}
