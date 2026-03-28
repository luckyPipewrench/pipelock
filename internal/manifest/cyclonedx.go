// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"crypto/rand"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const propertyPrefix = "pipelock:"

// ToCycloneDX converts a Manifest into a CycloneDX 1.6 BOM.
func ToCycloneDX(m Manifest) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.Version = 1
	bom.SerialNumber = newSerialNumber()

	ts := m.StartedAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	bom.Metadata = &cdx.Metadata{
		Timestamp: ts.Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type: cdx.ComponentTypeApplication,
					Name: "pipelock",
					Properties: &[]cdx.Property{
						{Name: propertyPrefix + "role", Value: "session-manifest-exporter"},
					},
				},
			},
		},
		Properties: &[]cdx.Property{
			{Name: propertyPrefix + "session-id", Value: m.SessionID},
			{Name: propertyPrefix + "transport", Value: m.Transport},
			{Name: propertyPrefix + "mode", Value: m.Policy.Mode},
			{Name: propertyPrefix + "config-hash", Value: m.Policy.ConfigHash},
			{Name: propertyPrefix + "fingerprint", Value: m.Fingerprint},
		},
	}

	components := make([]cdx.Component, 0, len(m.Tools.Declared))
	for _, tool := range m.Tools.Declared {
		component := cdx.Component{
			Type:        cdx.ComponentTypeApplication,
			Name:        tool.Name,
			BOMRef:      "tool-" + tool.Name,
			Description: tool.Description,
			Properties: &[]cdx.Property{
				{Name: propertyPrefix + "kind", Value: "declared-tool"},
			},
		}
		components = append(components, component)
	}

	bom.Components = &components
	return bom
}

// newSerialNumber generates a CycloneDX-compliant UUID URN.
func newSerialNumber() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
