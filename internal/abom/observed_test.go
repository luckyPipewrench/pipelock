// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package abom_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/abom"
)

func TestNewObservedInventory(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)
	if obs.SessionID != testSessionID {
		t.Errorf("SessionID = %q, want %q", obs.SessionID, testSessionID)
	}
	if obs.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
	if len(obs.MCPServers) != 0 {
		t.Errorf("MCPServers should be empty, got %d", len(obs.MCPServers))
	}
	if len(obs.Domains) != 0 {
		t.Errorf("Domains should be empty, got %d", len(obs.Domains))
	}
}

func TestObservedInventory_RecordMCPServer(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	tools := []string{"pods_list", "pods_get"}
	command := []string{"kubectl-mcp"}
	obs.RecordMCPServer(testServerK8s, testTransport, tools, command)

	if len(obs.MCPServers) != 1 {
		t.Fatalf("expected 1 MCP server, got %d", len(obs.MCPServers))
	}
	srv := obs.MCPServers[testServerK8s]
	if srv.Name != testServerK8s {
		t.Errorf("Name = %q, want %q", srv.Name, testServerK8s)
	}
	if srv.Transport != testTransport {
		t.Errorf("Transport = %q, want %q", srv.Transport, testTransport)
	}
	if len(srv.Tools) != 2 {
		t.Errorf("Tools count = %d, want 2", len(srv.Tools))
	}
	if len(srv.Command) != 1 {
		t.Errorf("Command count = %d, want 1", len(srv.Command))
	}
}

func TestObservedInventory_RecordMCPServer_UpdateTools(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list"}, nil)
	obs.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list", "pods_get", "nodes_top"}, nil)

	srv := obs.MCPServers[testServerK8s]
	if len(srv.Tools) != 3 {
		t.Errorf("Tools should be updated to 3, got %d", len(srv.Tools))
	}
}

func TestObservedInventory_RecordMCPServer_NilTools(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordMCPServer(testServerK8s, testTransport, []string{"initial"}, nil)
	obs.RecordMCPServer(testServerK8s, testTransport, nil, nil) // nil tools should not overwrite

	srv := obs.MCPServers[testServerK8s]
	if len(srv.Tools) != 1 {
		t.Errorf("nil tools should not overwrite, got %d tools", len(srv.Tools))
	}
}

func TestObservedInventory_RecordToolCall(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	// Tool call on unknown server should auto-create
	obs.RecordToolCall(testServerK8s)
	obs.RecordToolCall(testServerK8s)
	obs.RecordToolCall(testServerK8s)

	srv := obs.MCPServers[testServerK8s]
	if srv.ToolCalls != 3 {
		t.Errorf("ToolCalls = %d, want 3", srv.ToolCalls)
	}
}

func TestObservedInventory_RecordToolCall_ExistingServer(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list"}, nil)
	obs.RecordToolCall(testServerK8s)

	srv := obs.MCPServers[testServerK8s]
	if srv.ToolCalls != 1 {
		t.Errorf("ToolCalls = %d, want 1", srv.ToolCalls)
	}
	if srv.Transport != testTransport {
		t.Errorf("Transport should be preserved: %q", srv.Transport)
	}
}

func TestObservedInventory_RecordDomain(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordDomain("api.example.com", 1024, 512)

	if len(obs.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(obs.Domains))
	}
	dom := obs.Domains["api.example.com"]
	if dom.Requests != 1 {
		t.Errorf("Requests = %d, want 1", dom.Requests)
	}
	if dom.BytesIn != 1024 {
		t.Errorf("BytesIn = %d, want 1024", dom.BytesIn)
	}
	if dom.BytesOut != 512 {
		t.Errorf("BytesOut = %d, want 512", dom.BytesOut)
	}
	if dom.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set")
	}
	if dom.LastSeen.IsZero() {
		t.Error("LastSeen should be set")
	}
}

func TestObservedInventory_RecordDomain_Accumulates(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordDomain("api.example.com", 100, 50)
	obs.RecordDomain("api.example.com", 200, 100)

	dom := obs.Domains["api.example.com"]
	if dom.Requests != 2 {
		t.Errorf("Requests = %d, want 2", dom.Requests)
	}
	if dom.BytesIn != 300 {
		t.Errorf("BytesIn = %d, want 300", dom.BytesIn)
	}
	if dom.BytesOut != 150 {
		t.Errorf("BytesOut = %d, want 150", dom.BytesOut)
	}
}

func TestObservedInventory_Finalize(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	if !obs.EndTime.IsZero() {
		t.Error("EndTime should be zero before Finalize")
	}

	obs.Finalize()

	if obs.EndTime.IsZero() {
		t.Error("EndTime should be set after Finalize")
	}
}

func TestObservedInventory_Snapshot(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)
	obs.RecordMCPServer(testServerK8s, testTransport, nil, nil)
	obs.RecordMCPServer(testServerScrpl, testTransport, nil, nil)

	names := obs.Snapshot()
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %d", len(names))
	}

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found[testServerK8s] {
		t.Error("missing kubernetes in snapshot")
	}
	if !found[testServerScrpl] {
		t.Error("missing scrapling in snapshot")
	}
}

func TestObservedInventory_Snapshot_Empty(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)
	names := obs.Snapshot()
	if len(names) != 0 {
		t.Errorf("expected 0 names, got %d", len(names))
	}
}

func TestObservedInventory_ConcurrentAccess(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	const goroutines = 10
	const opsPerGoroutine = 50
	var wg sync.WaitGroup

	for g := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			serverName := fmt.Sprintf("server-%d", id)
			domain := fmt.Sprintf("domain-%d.example.com", id)
			for range opsPerGoroutine {
				obs.RecordMCPServer(serverName, testTransport, nil, nil)
				obs.RecordToolCall(serverName)
				obs.RecordDomain(domain, 100, 50)
				obs.Snapshot()
			}
		}(g)
	}

	wg.Wait()

	if len(obs.MCPServers) != goroutines {
		t.Errorf("expected %d servers, got %d", goroutines, len(obs.MCPServers))
	}
	if len(obs.Domains) != goroutines {
		t.Errorf("expected %d domains, got %d", goroutines, len(obs.Domains))
	}

	// Verify tool call counts
	for _, srv := range obs.MCPServers {
		if srv.ToolCalls != opsPerGoroutine {
			t.Errorf("server %s ToolCalls = %d, want %d", srv.Name, srv.ToolCalls, opsPerGoroutine)
		}
	}
}

func TestObservedInventory_MultipleDomains(t *testing.T) {
	obs := abom.NewObservedInventory(testSessionID)

	obs.RecordDomain("api.example.com", 100, 50)
	obs.RecordDomain("cdn.example.com", 200, 0)
	obs.RecordDomain("auth.example.com", 50, 25)

	if len(obs.Domains) != 3 {
		t.Errorf("expected 3 domains, got %d", len(obs.Domains))
	}
}
