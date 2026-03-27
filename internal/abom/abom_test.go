// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package abom_test

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/luckyPipewrench/pipelock/internal/abom"
)

const (
	testMode        = "strict"
	testTransport   = "stdio"
	testSessionID   = "test-session"
	testServerK8s   = "kubernetes"
	testServerScrpl = "scrapling"
)

func TestGenerate_DeclaredOnly(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode:       testMode,
		DLPEnabled: true,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: testServerK8s, Command: []string{"kubectl-mcp"}, Transport: testTransport},
		},
	}
	bom, completeness := abom.Generate(declared, nil)

	if bom.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("SpecVersion = %v, want %v", bom.SpecVersion, cdx.SpecVersion1_6)
	}
	if bom.Components == nil {
		t.Fatal("Components should not be nil")
	}

	// 1 MCP server + 1 config
	const expectedComponents = 2
	if len(*bom.Components) != expectedComponents {
		t.Errorf("expected %d components, got %d", expectedComponents, len(*bom.Components))
	}

	if completeness.DeclaredCount != 1 {
		t.Errorf("DeclaredCount = %d, want 1", completeness.DeclaredCount)
	}
	if completeness.ObservedCount != 0 {
		t.Errorf("ObservedCount = %d, want 0", completeness.ObservedCount)
	}
	if completeness.Confidence != 0.0 {
		t.Errorf("Confidence = %f, want 0.0", completeness.Confidence)
	}
}

func TestGenerate_DeclaredPlusObserved(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: testServerK8s, Transport: testTransport},
			{Name: testServerScrpl, Transport: testTransport},
		},
	}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list", "pods_get"}, nil)
	observed.RecordToolCall(testServerK8s)
	observed.RecordToolCall(testServerK8s)
	// scrapling declared but not observed (dormant)

	bom, completeness := abom.Generate(declared, observed)

	if completeness.DeclaredCount != 2 {
		t.Errorf("DeclaredCount = %d, want 2", completeness.DeclaredCount)
	}
	if completeness.ObservedCount != 1 {
		t.Errorf("ObservedCount = %d, want 1", completeness.ObservedCount)
	}
	if completeness.DormantCount != 1 {
		t.Errorf("DormantCount = %d, want 1", completeness.DormantCount)
	}

	const expectedConfidence = 0.5
	const confidenceDelta = 0.01
	if completeness.Confidence < expectedConfidence-confidenceDelta ||
		completeness.Confidence > expectedConfidence+confidenceDelta {
		t.Errorf("Confidence = %f, want ~%f", completeness.Confidence, expectedConfidence)
	}

	// Check dormant annotation on scrapling
	for _, c := range *bom.Components {
		if c.Name == testServerScrpl {
			found := false
			if c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "pipelock:status" && p.Value == abom.StatusDormant {
						found = true
					}
				}
			}
			if !found {
				t.Error("dormant server should have pipelock:status=dormant property")
			}
		}
	}
}

func TestGenerate_UnexpectedServer(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: testServerK8s, Transport: testTransport},
		},
	}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordMCPServer(testServerK8s, testTransport, nil, nil)
	observed.RecordMCPServer("unknown-server", "http", nil, nil) // Undeclared

	_, completeness := abom.Generate(declared, observed)

	if completeness.UnexpectedCount != 1 {
		t.Errorf("UnexpectedCount = %d, want 1", completeness.UnexpectedCount)
	}
	if completeness.ObservedCount != 1 {
		t.Errorf("ObservedCount = %d, want 1", completeness.ObservedCount)
	}
}

func TestGenerate_FullConfidence(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: testServerK8s, Transport: testTransport},
		},
	}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list"}, nil)

	_, completeness := abom.Generate(declared, observed)

	const expectedConfidence = 1.0
	const confidenceDelta = 0.01
	if completeness.Confidence < expectedConfidence-confidenceDelta {
		t.Errorf("Confidence = %f, want ~%f", completeness.Confidence, expectedConfidence)
	}
	if completeness.DormantCount != 0 {
		t.Errorf("DormantCount = %d, want 0", completeness.DormantCount)
	}
}

func TestGenerate_NoDeclaredServers(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
	}
	bom, completeness := abom.Generate(declared, nil)

	if completeness.DeclaredCount != 0 {
		t.Errorf("DeclaredCount = %d, want 0", completeness.DeclaredCount)
	}
	if completeness.Confidence != 0.0 {
		t.Errorf("Confidence = %f, want 0.0", completeness.Confidence)
	}

	// Should still have config component
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Error("expected 1 component (config)")
	}
}

func TestGenerate_WithDomains(t *testing.T) {
	declared := abom.DeclaredInventory{Mode: testMode}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordDomain("api.example.com", 1024, 512)
	observed.RecordDomain("cdn.example.com", 2048, 0)

	bom, _ := abom.Generate(declared, observed)

	// Config + 2 domains
	const expectedComponents = 3
	if len(*bom.Components) != expectedComponents {
		t.Errorf("expected %d components, got %d", expectedComponents, len(*bom.Components))
	}

	// Verify domain properties
	for _, c := range *bom.Components {
		if c.Name == "api.example.com" {
			if c.Type != cdx.ComponentTypeData {
				t.Errorf("domain type = %s, want data", c.Type)
			}
			found := false
			if c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "pipelock:requests" && p.Value == "1" {
						found = true
					}
				}
			}
			if !found {
				t.Error("domain should have pipelock:requests property")
			}
		}
	}
}

func TestGenerate_Metadata(t *testing.T) {
	declared := abom.DeclaredInventory{Mode: testMode}
	bom, _ := abom.Generate(declared, nil)

	if bom.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("Metadata.Timestamp should be set")
	}
	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("Metadata.Tools.Components should not be nil")
	}
	tools := *bom.Metadata.Tools.Components
	if len(tools) != 1 || tools[0].Name != "pipelock" {
		t.Error("Metadata should list pipelock as tool")
	}
}

func TestGenerate_MCPServerWithUpstream(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: "remote-mcp", Upstream: "http://localhost:8080/path?" + "token=sec" + "ret", Transport: "http"},
		},
	}
	bom, _ := abom.Generate(declared, nil)

	for _, c := range *bom.Components {
		if c.Name == "remote-mcp" {
			if c.Properties == nil {
				t.Fatal("expected properties on remote-mcp component")
			}
			for _, p := range *c.Properties {
				if p.Name == "pipelock:upstream" {
					// Must be stripped to scheme+host only
					if p.Value != "http://localhost" {
						t.Errorf("upstream should be redacted to scheme+host, got %q", p.Value)
					}
				}
			}
		}
	}
}

func TestGenerate_CommandRedactedToBasename(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{
				Name:      "test-mcp",
				Command:   []string{"/usr/local/bin/my-server", "--" + "token=sec" + "ret123", "--port=8080"},
				Transport: testTransport,
			},
		},
	}
	bom, _ := abom.Generate(declared, nil)

	for _, c := range *bom.Components {
		if c.Name != "test-mcp" {
			continue
		}
		if c.Properties == nil {
			t.Fatal("expected properties")
		}
		var commandVal string
		var redactedFlag bool
		for _, p := range *c.Properties {
			if p.Name == "pipelock:command" {
				commandVal = p.Value
			}
			if p.Name == "pipelock:command_redacted" && p.Value == "true" {
				redactedFlag = true
			}
		}
		if commandVal != "my-server" {
			t.Errorf("command should be basename only, got %q", commandVal)
		}
		if !redactedFlag {
			t.Error("command_redacted property should be set to true")
		}
	}
}

func TestGenerate_UpstreamStripsUserinfoAndQuery(t *testing.T) {
	// Build URL with credentials at runtime to avoid gosec G101
	upstream := "https://user:" + "password" + "@api.example.com:9090/v1?key=secret#frag"
	declared := abom.DeclaredInventory{
		Mode: testMode,
		MCPServers: []abom.DeclaredMCPServer{
			{
				Name:      "auth-mcp",
				Upstream:  upstream,
				Transport: "http",
			},
		},
	}
	bom, _ := abom.Generate(declared, nil)

	for _, c := range *bom.Components {
		if c.Name != "auth-mcp" {
			continue
		}
		if c.Properties == nil {
			t.Fatal("expected properties")
		}
		for _, p := range *c.Properties {
			if p.Name == "pipelock:upstream" {
				if p.Value != "https://api.example.com" {
					t.Errorf("upstream should strip userinfo/port/path/query/fragment, got %q", p.Value)
				}
			}
		}
	}
}

func TestGenerate_ObservedWithTools(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode:       testMode,
		MCPServers: []abom.DeclaredMCPServer{{Name: testServerK8s, Transport: testTransport}},
	}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list", "pods_get", "nodes_top"}, nil)

	bom, _ := abom.Generate(declared, observed)

	for _, c := range *bom.Components {
		if c.Name == testServerK8s {
			foundTools := false
			foundCount := false
			if c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "pipelock:tools" {
						foundTools = true
					}
					if p.Name == "pipelock:tool-count" && p.Value == "3" {
						foundCount = true
					}
				}
			}
			if !foundTools {
				t.Error("active server should have pipelock:tools property")
			}
			if !foundCount {
				t.Error("active server should have pipelock:tool-count=3")
			}
		}
	}
}

func TestGenerate_ConfigProperties(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode:       testMode,
		DLPEnabled: true,
	}
	bom, _ := abom.Generate(declared, nil)

	for _, c := range *bom.Components {
		if c.Name == "pipelock-config" {
			if c.Type != cdx.ComponentTypeData {
				t.Errorf("config type = %s, want data", c.Type)
			}
			modeFound := false
			dlpFound := false
			if c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "pipelock:mode" && p.Value == testMode {
						modeFound = true
					}
					if p.Name == "pipelock:dlp-enabled" && p.Value == "true" {
						dlpFound = true
					}
				}
			}
			if !modeFound {
				t.Error("config should have pipelock:mode property")
			}
			if !dlpFound {
				t.Error("config should have pipelock:dlp-enabled property")
			}
		}
	}
}

func TestGenerate_JSONSerializable(t *testing.T) {
	declared := abom.DeclaredInventory{
		Mode:       testMode,
		DLPEnabled: true,
		MCPServers: []abom.DeclaredMCPServer{
			{Name: testServerK8s, Transport: testTransport, Command: []string{"kubectl-mcp"}},
		},
	}
	observed := abom.NewObservedInventory(testSessionID)
	observed.RecordMCPServer(testServerK8s, testTransport, []string{"pods_list"}, nil)
	observed.RecordDomain("api.example.com", 100, 50)

	bom, _ := abom.Generate(declared, observed)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON output should not be empty")
	}

	// Verify it round-trips
	var parsed cdx.BOM
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}
}

func TestGenerate_SerialNumber(t *testing.T) {
	declared := abom.DeclaredInventory{Mode: testMode}
	bom1, _ := abom.Generate(declared, nil)
	bom2, _ := abom.Generate(declared, nil)

	if bom1.SerialNumber == "" {
		t.Error("SerialNumber should be set")
	}
	// Serial numbers should be unique (based on UnixNano)
	if bom1.SerialNumber == bom2.SerialNumber {
		t.Error("SerialNumbers should be unique across generations")
	}
}
