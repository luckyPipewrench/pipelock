// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package abom

import (
	"sync"
	"time"
)

// ObservedInventory collects runtime data from a pipelock session.
// All methods are thread-safe.
type ObservedInventory struct {
	mu         sync.Mutex
	MCPServers map[string]*ObservedMCPServer
	Domains    map[string]*ObservedDomain
	StartTime  time.Time
	EndTime    time.Time
	SessionID  string
}

// ObservedMCPServer tracks runtime observations for an MCP server.
type ObservedMCPServer struct {
	Name      string
	Transport string
	Tools     []string
	ToolCalls int
	Command   []string
}

// ObservedDomain tracks runtime observations for a domain.
type ObservedDomain struct {
	Domain    string
	Requests  int
	BytesIn   int64
	BytesOut  int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewObservedInventory creates a new empty collector.
func NewObservedInventory(sessionID string) *ObservedInventory {
	return &ObservedInventory{
		MCPServers: make(map[string]*ObservedMCPServer),
		Domains:    make(map[string]*ObservedDomain),
		StartTime:  time.Now().UTC(),
		SessionID:  sessionID,
	}
}

// RecordMCPServer registers or updates an MCP server observation.
func (o *ObservedInventory) RecordMCPServer(name, transport string, tools []string, command []string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	srv, exists := o.MCPServers[name]
	if !exists {
		srv = &ObservedMCPServer{
			Name:      name,
			Transport: transport,
			Command:   command,
		}
		o.MCPServers[name] = srv
	}

	// Update tools if provided (may grow as server advertises more tools)
	if len(tools) > 0 {
		srv.Tools = tools
	}
}

// RecordToolCall increments the tool call counter for an MCP server.
func (o *ObservedInventory) RecordToolCall(serverName string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	srv, exists := o.MCPServers[serverName]
	if !exists {
		srv = &ObservedMCPServer{Name: serverName}
		o.MCPServers[serverName] = srv
	}
	srv.ToolCalls++
}

// RecordDomain registers or updates a domain observation.
func (o *ObservedInventory) RecordDomain(domain string, bytesIn, bytesOut int64) {
	o.mu.Lock()
	defer o.mu.Unlock()

	now := time.Now().UTC()
	dom, exists := o.Domains[domain]
	if !exists {
		dom = &ObservedDomain{
			Domain:    domain,
			FirstSeen: now,
		}
		o.Domains[domain] = dom
	}
	dom.Requests++
	dom.BytesIn += bytesIn
	dom.BytesOut += bytesOut
	dom.LastSeen = now
}

// Finalize marks the observation period as complete.
func (o *ObservedInventory) Finalize() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.EndTime = time.Now().UTC()
}

// Snapshot returns a copy of the current observed MCP server names.
// Useful for logging without holding the lock.
func (o *ObservedInventory) Snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	names := make([]string, 0, len(o.MCPServers))
	for name := range o.MCPServers {
		names = append(names, name)
	}
	return names
}
