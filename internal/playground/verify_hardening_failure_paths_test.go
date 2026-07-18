// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardeningBundleParserRejectsCorruptionAndMemberFlood(t *testing.T) {
	t.Parallel()

	var corrupt bytes.Buffer
	gz := gzip.NewWriter(&corrupt)
	if _, err := gz.Write([]byte("not a tar stream")); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if _, err := ExtractRunArtifactsFromBundle(corrupt.Bytes()); err == nil ||
		!strings.Contains(err.Error(), "read tar") {
		t.Fatalf("corrupt archive error = %v", err)
	}

	var flooded bytes.Buffer
	gz = gzip.NewWriter(&flooded)
	tw := tar.NewWriter(gz)
	for i := 0; i <= maxBundleMembers; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("directory-%02d", i),
			Typeflag: tar.TypeDir,
			Mode:     0o750,
		}); err != nil {
			t.Fatalf("write header %d: %v", i, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if _, err := ExtractRunArtifactsFromBundle(flooded.Bytes()); err == nil ||
		!strings.Contains(err.Error(), "too many members") {
		t.Fatalf("member flood error = %v", err)
	}

	if name, retain, err := bundleArtifactName("directory", tar.TypeDir); err != nil || retain || name != "" {
		t.Fatalf("directory member = (%q, %v, %v), want ignored", name, retain, err)
	}
}

func TestHardeningVerifyRunPreservesEveryArtifactReadFailure(t *testing.T) {
	t.Parallel()

	names := []string{
		launchManifestFile,
		witnessFile,
		redWitnessFile,
		hostContainmentWitnessFile,
		filepath.Join(packetSubdir, packetJSONFile),
		filepath.Join(packetSubdir, packetEvidenceFile),
		filepath.Join(packetSubdir, packetManifestFile),
	}
	for targetIndex, target := range names {
		t.Run(filepath.Base(target), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, packetSubdir), 0o750); err != nil {
				t.Fatalf("mkdir packet: %v", err)
			}
			for i, name := range names {
				fullPath := filepath.Join(dir, name)
				if i == targetIndex {
					if err := os.Mkdir(fullPath, 0o750); err != nil {
						t.Fatalf("mkdir target %s: %v", name, err)
					}
					break
				}
				if err := os.WriteFile(fullPath, []byte("{}"), 0o600); err != nil {
					t.Fatalf("write predecessor %s: %v", name, err)
				}
			}
			rep, err := VerifyRun(dir, "")
			if err == nil || !strings.Contains(err.Error(), "cannot read") {
				t.Fatalf("VerifyRun report=%+v error=%v", rep, err)
			}
			if rep.OK {
				t.Fatal("VerifyRun passed after an artifact read failure")
			}
		})
	}
}

func TestHardeningVerifierReasonsRemainFailClosedAndSpecific(t *testing.T) {
	t.Parallel()

	if got := hostContainmentEnforcedReason(HostContainmentWitness{}); !strings.Contains(got, "older format") {
		t.Fatalf("missing proxy reason = %q", got)
	}
	if got := hostContainmentEnforcedReason(HostContainmentWitness{
		ProxyTarget:     "127.0.0.1:8888",
		ProxyAgentProbe: ProbeResult{Target: "127.0.0.1:8888"},
	}); !strings.Contains(got, "local escape probes") {
		t.Fatalf("missing local probe reason = %q", got)
	}
	if got := hostContainmentEnforcedReason(HostContainmentWitness{
		ProxyTarget:      "127.0.0.1:8888",
		ProxyAgentProbe:  ProbeResult{Target: "127.0.0.1:8888"},
		LocalAgentProbes: []ProbeResult{{Target: "unix:///run/service.sock", Blocked: true}},
	}); !strings.Contains(got, "not proven") {
		t.Fatalf("generic enforcement reason = %q", got)
	}

	lm := LaunchManifest{CanaryID: "canary", CollectorPubKey: strings.Repeat("00", 32)}
	rc := &RedCaseResult{RedWitnessDigest: "wrong"}
	if _, reasons := verifyRedWitnessArtifactBytes([]byte("{"), lm, rc); len(reasons) != 1 ||
		!strings.Contains(reasons[0], "malformed") {
		t.Fatalf("malformed red witness reasons = %v", reasons)
	}
	if _, reasons := verifyRedWitnessArtifactBytes([]byte("{}"), lm, rc); len(reasons) < 4 {
		t.Fatalf("invalid red witness reasons = %v, want multiple independent failures", reasons)
	}

	if err := verifyLiveDemoSemanticsBytes(nil, nil, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "missing packet manifest") {
		t.Fatalf("missing manifest error = %v", err)
	}
	if err := verifyLiveDemoSemanticsBytes([]byte("{"), nil, lm, Witness{}); err == nil ||
		!strings.Contains(err.Error(), "malformed packet manifest") {
		t.Fatalf("malformed manifest error = %v", err)
	}
	if err := verifyLiveDemoReceipts(nil, LaunchManifest{
		AgentKind:  AgentKindModel,
		ScenarioID: "unsupported",
	}, Witness{}); err == nil || !strings.Contains(err.Error(), "unsupported model-mode scenario") {
		t.Fatalf("model scenario error = %v", err)
	}

	rep := finalize(VerifyReport{}, requiredChecks)
	if rep.OK {
		t.Fatal("finalize accepted an empty check set")
	}
}
