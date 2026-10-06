// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRenderSessionContractIncludesFilesystemProfile(t *testing.T) {
	var buf bytes.Buffer
	err := renderSessionContract(&buf, sessionContract{
		Command:         "pipelock contain run",
		Tool:            "claude",
		AgentUser:       "pipelock-agent",
		ProxyURL:        "http://127.0.0.1:8080",
		PostureCapsule:  "/var/lib/pipelock/contain/posture/proof.json",
		PrivateTmp:      true,
		FilesystemMode:  config.ContainmentFilesystemModeEnforce,
		FilesystemBinds: []string{"BindPaths=/srv/agent-home:/srv/agent-home:norbind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"filesystem profile: enforce",
		"filesystem binds:",
		"BindPaths=/srv/agent-home:/srv/agent-home:norbind",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("contract missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := renderSessionContract(&buf, sessionContract{
		Tool:           "claude",
		FilesystemMode: config.ContainmentFilesystemModeEnforce,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "filesystem binds: (none)") {
		t.Fatalf("empty enforce binds = %q", buf.String())
	}
}

func TestFilesystemContractBindsAndEvidenceStayEmptyUntilEnforce(t *testing.T) {
	off := filesystemProfile{Mode: config.ContainmentFilesystemModeOff, BindPaths: []string{"/srv:/srv:norbind"}}
	if binds := filesystemContractBinds(off); binds != nil {
		t.Fatalf("off binds = %v", binds)
	}
	if mode, digest := filesystemEvidenceFields(off); mode != "" || digest != "" {
		t.Fatalf("off evidence = %q %q", mode, digest)
	}

	profile := filesystemProfile{
		Mode:              config.ContainmentFilesystemModeEnforce,
		BindPaths:         []string{"/srv/workspace:/srv/workspace:norbind"},
		BindReadOnlyPaths: []string{"/tmp/.X11-unix/X7:/tmp/.X11-unix/X7:rbind"},
	}
	binds := filesystemContractBinds(profile)
	if len(binds) != 2 || binds[0] != "BindPaths=/srv/workspace:/srv/workspace:norbind" || binds[1] != "BindReadOnlyPaths=/tmp/.X11-unix/X7:/tmp/.X11-unix/X7:rbind" {
		t.Fatalf("binds = %v", binds)
	}
	mode, digest := filesystemEvidenceFields(profile)
	if mode != config.ContainmentFilesystemModeEnforce || digest == "" || digest != filesystemBindsDigest(profile) {
		t.Fatalf("evidence = %q %q", mode, digest)
	}
}
