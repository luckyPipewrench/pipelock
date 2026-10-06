// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"strings"
	"testing"
)

func TestRenderProofMarkdownIncludesFilesystemEvidence(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	text := RenderProofMarkdown(&Capsule{
		SchemaVersion: SchemaVersion,
		Evidence: EvidenceBundle{
			ContainLaunch: &ContainLaunchEvidence{
				Launcher:              "/usr/local/lib/pipelock/plk-launch",
				AgentUser:             "pipelock-agent",
				TargetUID:             "966",
				TargetGID:             "966",
				Tool:                  "claude",
				FilesystemMode:        "enforce",
				FilesystemBindsSHA256: digest,
			},
			Containment: &ContainmentEvidence{
				Mode:                  ContainmentModeKernelNFTOwnerMatch,
				FilesystemMode:        "enforce",
				FilesystemBindsSHA256: digest,
			},
		},
	})
	if strings.Count(text, "- Filesystem mode: `enforce`") != 1 || strings.Count(text, "- Containment filesystem mode: `enforce`") != 1 || strings.Count(text, "- Filesystem binds SHA-256: `"+digest+"`") != 1 || strings.Count(text, "- Containment filesystem binds SHA-256: `"+digest+"`") != 1 {
		t.Fatalf("markdown =\n%s", text)
	}

	omitted := RenderProofMarkdown(&Capsule{SchemaVersion: SchemaVersion})
	if strings.Contains(omitted, "Filesystem mode:") {
		t.Fatalf("empty capsule rendered filesystem evidence:\n%s", omitted)
	}

	// Evidence present but filesystem mode empty: both renderers must omit
	// the filesystem lines rather than print an empty mode or digest.
	offMode := RenderProofMarkdown(&Capsule{
		SchemaVersion: SchemaVersion,
		Evidence: EvidenceBundle{
			ContainLaunch: &ContainLaunchEvidence{
				Launcher:  "/usr/local/lib/pipelock/plk-launch",
				AgentUser: "pipelock-agent",
				TargetUID: "966",
				TargetGID: "966",
				Tool:      "claude",
			},
			Containment: &ContainmentEvidence{Mode: ContainmentModeKernelNFTOwnerMatch},
		},
	})
	for _, line := range []string{"Filesystem mode:", "Filesystem binds SHA-256:", "Containment filesystem mode:", "Containment filesystem binds SHA-256:"} {
		if strings.Contains(offMode, line) {
			t.Fatalf("empty filesystem mode rendered %q:\n%s", line, offMode)
		}
	}
}
