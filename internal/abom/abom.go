// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package abom generates CycloneDX 1.6 runtime Agent Bill of Materials
// with declared vs observed views and confidence scoring.
package abom

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Property name prefix for pipelock-specific properties.
const propertyPrefix = "pipelock:"

// Status values for pipelock:status property.
const (
	StatusActive     = "active"
	StatusDormant    = "dormant"
	StatusUnexpected = "unexpected"
)

// DeclaredInventory comes from pipelock configuration.
type DeclaredInventory struct {
	MCPServers []DeclaredMCPServer
	Mode       string
	DLPEnabled bool
}

// DeclaredMCPServer represents an MCP server from config.
type DeclaredMCPServer struct {
	Name      string
	Command   []string
	Upstream  string
	Transport string
}

// Completeness tracks declared vs observed coverage.
type Completeness struct {
	DeclaredCount   int
	ObservedCount   int
	DormantCount    int
	UnexpectedCount int
	Confidence      float64 // 0.0-1.0
}

// Generate produces a CycloneDX 1.6 BOM from declared + observed inventory.
// If observed is nil, only declared inventory is included (zero confidence).
func Generate(declared DeclaredInventory, observed *ObservedInventory) (*cdx.BOM, Completeness) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.Version = 1
	bom.SerialNumber = fmt.Sprintf("urn:uuid:pipelock-abom-%d", time.Now().UnixNano())

	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type: cdx.ComponentTypeApplication,
					Name: "pipelock",
					Properties: &[]cdx.Property{
						{Name: propertyPrefix + "role", Value: "agent-firewall"},
					},
				},
			},
		},
	}

	var components []cdx.Component
	comp := computeCompleteness(declared, observed)

	// Add MCP server components
	declaredNames := make(map[string]bool, len(declared.MCPServers))
	for _, srv := range declared.MCPServers {
		declaredNames[srv.Name] = true
		c := mcpServerComponent(srv)

		// Check observed status
		if observed != nil {
			observed.mu.Lock()
			obs, found := observed.MCPServers[srv.Name]
			observed.mu.Unlock()

			if found {
				addObservedProperties(&c, obs)
			} else {
				appendProperty(&c, propertyPrefix+"status", StatusDormant)
			}
		} else {
			appendProperty(&c, propertyPrefix+"status", StatusDormant)
		}

		components = append(components, c)
	}

	// Add observed-but-undeclared servers
	if observed != nil {
		observed.mu.Lock()
		for name, obs := range observed.MCPServers {
			if !declaredNames[name] {
				c := cdx.Component{
					Type:   cdx.ComponentTypeApplication,
					Name:   name,
					BOMRef: "mcp-server-" + name,
				}
				addObservedProperties(&c, obs)
				appendProperty(&c, propertyPrefix+"status", StatusUnexpected)
				components = append(components, c)
			}
		}
		observed.mu.Unlock()
	}

	// Add observed domains as data components
	if observed != nil {
		observed.mu.Lock()
		for _, dom := range observed.Domains {
			c := cdx.Component{
				Type:   cdx.ComponentTypeData,
				Name:   dom.Domain,
				BOMRef: "domain-" + dom.Domain,
				Properties: &[]cdx.Property{
					{Name: propertyPrefix + "requests", Value: fmt.Sprintf("%d", dom.Requests)},
					{Name: propertyPrefix + "bytes-in", Value: fmt.Sprintf("%d", dom.BytesIn)},
					{Name: propertyPrefix + "bytes-out", Value: fmt.Sprintf("%d", dom.BytesOut)},
					{Name: propertyPrefix + "first-seen", Value: dom.FirstSeen.UTC().Format(time.RFC3339)},
					{Name: propertyPrefix + "last-seen", Value: dom.LastSeen.UTC().Format(time.RFC3339)},
				},
			}
			components = append(components, c)
		}
		observed.mu.Unlock()
	}

	// Add pipelock config as a data component
	configComp := cdx.Component{
		Type:   cdx.ComponentTypeData,
		Name:   "pipelock-config",
		BOMRef: "pipelock-config",
		Properties: &[]cdx.Property{
			{Name: propertyPrefix + "mode", Value: declared.Mode},
			{Name: propertyPrefix + "dlp-enabled", Value: fmt.Sprintf("%t", declared.DLPEnabled)},
		},
	}
	components = append(components, configComp)

	bom.Components = &components
	return bom, comp
}

// mcpServerComponent builds a CycloneDX component for a declared MCP server.
// Command lines are redacted to basename only (strips paths and arguments that
// may contain credentials). Upstream URLs are stripped to scheme+host.
func mcpServerComponent(srv DeclaredMCPServer) cdx.Component {
	c := cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		Name:   srv.Name,
		BOMRef: "mcp-server-" + srv.Name,
	}

	props := []cdx.Property{
		{Name: propertyPrefix + "transport", Value: srv.Transport},
	}
	if len(srv.Command) > 0 {
		props = append(props, cdx.Property{
			Name:  propertyPrefix + "command",
			Value: filepath.Base(srv.Command[0]),
		})
		props = append(props, cdx.Property{
			Name:  propertyPrefix + "command_redacted",
			Value: "true",
		})
	}
	if srv.Upstream != "" {
		props = append(props, cdx.Property{
			Name:  propertyPrefix + "upstream",
			Value: redactUpstream(srv.Upstream),
		})
	}
	c.Properties = &props
	return c
}

// redactUpstream strips a URL to scheme + hostname only, removing userinfo,
// path, query, and fragment that may contain credentials.
func redactUpstream(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<redacted>"
	}
	return u.Scheme + "://" + u.Hostname()
}

// addObservedProperties appends runtime observation data to a component.
func addObservedProperties(c *cdx.Component, obs *ObservedMCPServer) {
	appendProperty(c, propertyPrefix+"status", StatusActive)
	appendProperty(c, propertyPrefix+"tool-count", fmt.Sprintf("%d", len(obs.Tools)))
	appendProperty(c, propertyPrefix+"tool-calls", fmt.Sprintf("%d", obs.ToolCalls))
	if len(obs.Tools) > 0 {
		appendProperty(c, propertyPrefix+"tools", strings.Join(obs.Tools, ","))
	}
}

// appendProperty adds a property to a component, creating the slice if needed.
func appendProperty(c *cdx.Component, name, value string) {
	if c.Properties == nil {
		c.Properties = &[]cdx.Property{}
	}
	*c.Properties = append(*c.Properties, cdx.Property{Name: name, Value: value})
}

// computeCompleteness calculates the confidence score.
// Confidence = ObservedCount / DeclaredCount. If DeclaredCount is 0, confidence is 0.
func computeCompleteness(declared DeclaredInventory, observed *ObservedInventory) Completeness {
	comp := Completeness{
		DeclaredCount: len(declared.MCPServers),
	}

	if observed == nil {
		return comp
	}

	observed.mu.Lock()
	defer observed.mu.Unlock()

	declaredNames := make(map[string]bool, len(declared.MCPServers))
	for _, srv := range declared.MCPServers {
		declaredNames[srv.Name] = true
	}

	for name := range observed.MCPServers {
		if declaredNames[name] {
			comp.ObservedCount++
		} else {
			comp.UnexpectedCount++
		}
	}

	comp.DormantCount = comp.DeclaredCount - comp.ObservedCount
	if comp.DeclaredCount > 0 {
		comp.Confidence = float64(comp.ObservedCount) / float64(comp.DeclaredCount)
	}

	return comp
}
