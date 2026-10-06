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
}
