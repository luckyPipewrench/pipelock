// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VerifyKitOS is one supported visitor operating system for a live playground
// verification kit.
type VerifyKitOS string

const (
	VerifyKitOSLinux   VerifyKitOS = "linux"
	VerifyKitOSMacOS   VerifyKitOS = "macos"
	VerifyKitOSWindows VerifyKitOS = "windows"
)

// VerifyKitBinaries points at the real shipped pipelock-verifier binaries used
// to assemble per-session live verification kits.
type VerifyKitBinaries struct {
	Linux   string
	MacOS   string
	Windows string
}

// Path returns the configured verifier binary path for osName.
func (b VerifyKitBinaries) Path(osName VerifyKitOS) string {
	switch osName {
	case VerifyKitOSLinux:
		return b.Linux
	case VerifyKitOSMacOS:
		return b.MacOS
	case VerifyKitOSWindows:
		return b.Windows
	default:
		return ""
	}
}

// ParseVerifyKitOS normalizes a browser-supplied OS selector.
func ParseVerifyKitOS(raw string) (VerifyKitOS, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "linux":
		return VerifyKitOSLinux, nil
	case "macos", "mac", "darwin":
		return VerifyKitOSMacOS, nil
	case "windows", "win":
		return VerifyKitOSWindows, nil
	default:
		return "", fmt.Errorf("unsupported verify kit OS %q", raw)
	}
}

// verifyKitRunFiles lists every run-directory file the kit must include for the
// full VerifyRun trust chain. Missing files are tolerated only for optional
// artifacts (the host-containment witness is required only for contained runs
// and is extracted on a best-effort basis).
var verifyKitRequiredFiles = []string{
	"packet/packet.json",
	"packet/manifest.json",
	"packet/evidence.jsonl",
	launchManifestFile,
	witnessFile,
	redWitnessFile,
}

// verifyKitOptionalFiles are extracted when present but their absence does not
// fail the kit build.
var verifyKitOptionalFiles = []string{
	hostContainmentWitnessFile,
	"VERIFY.txt",
}

// BuildLiveVerifyKit builds a single-download, offline verification kit for one
// sealed live session. sessionTarGz must be the output of ArchiveRunForDownload.
// The kit embeds the real verifier binary and ALL run artifacts needed for the
// full VerifyRun trust chain (launch manifest, witnesses, receipt chain, etc.).
//
// The trust key is ALWAYS the compiled-in PublishedOrchestratorPubKeyHex. The
// kit never derives, extracts, or falls back to a key from the bundle -- a
// tampered bundle cannot ship its own key.
func BuildLiveVerifyKit(osName VerifyKitOS, verifierPath string, sessionTarGz []byte) ([]byte, string, error) {
	if verifierPath == "" {
		return nil, "", errors.New("verifier binary path is not configured")
	}
	verifier, err := os.ReadFile(filepath.Clean(verifierPath))
	if err != nil {
		return nil, "", fmt.Errorf("read verifier binary: %w", err)
	}
	files, err := extractLiveKitFiles(sessionTarGz)
	if err != nil {
		return nil, "", err
	}

	trustKey := PublishedOrchestratorPubKeyHex

	root := "pipelock-live-verify-" + string(osName)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if err := zipFile(zw, root+"/README.txt", []byte(liveKitReadme(osName)), 0o600); err != nil {
		return nil, "", err
	}
	scriptName, scriptBody, err := liveKitScript(osName, trustKey)
	if err != nil {
		return nil, "", err
	}
	if err := zipFile(zw, root+"/"+scriptName, []byte(scriptBody), 0o700); err != nil {
		return nil, "", err
	}

	binName := "pipelock-verifier"
	if osName == VerifyKitOSWindows {
		binName += ".exe"
	}
	if err := zipFile(zw, root+"/app/"+binName, verifier, 0o700); err != nil {
		return nil, "", err
	}

	// Pack required run-directory files -- all must be present.
	for _, name := range verifyKitRequiredFiles {
		data, ok := files[name]
		if !ok {
			return nil, "", fmt.Errorf("session bundle missing %s", name)
		}
		if err := zipFile(zw, root+"/app/run/"+name, data, 0o600); err != nil {
			return nil, "", err
		}
	}
	// Pack optional files when present.
	for _, name := range verifyKitOptionalFiles {
		data, ok := files[name]
		if !ok {
			continue
		}
		if err := zipFile(zw, root+"/app/run/"+name, data, 0o600); err != nil {
			return nil, "", err
		}
	}

	if err := zipFile(zw, root+"/app/run/verifier.txt", []byte(liveKitVerifierTxt(trustKey)), 0o600); err != nil {
		return nil, "", err
	}

	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("close verify kit zip: %w", err)
	}
	return buf.Bytes(), "pipelock-live-verify-" + string(osName) + ".zip", nil
}

func extractLiveKitFiles(sessionTarGz []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(sessionTarGz))
	if err != nil {
		return nil, fmt.Errorf("read session bundle gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// Build the set of files to extract.
	want := make(map[string]bool)
	for _, f := range verifyKitRequiredFiles {
		want[f] = true
	}
	for _, f := range verifyKitOptionalFiles {
		want[f] = true
	}

	files := make(map[string][]byte)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read session bundle tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := strings.CutPrefix(filepath.ToSlash(hdr.Name), downloadArchivePrefix+"/")
		if !ok {
			continue
		}
		if !want[name] {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read session bundle file %s: %w", name, err)
		}
		files[name] = data
	}
	return files, nil
}

func zipFile(zw *zip.Writer, name string, data []byte, mode os.FileMode) error {
	h := &zip.FileHeader{
		Name:     filepath.ToSlash(name),
		Method:   zip.Deflate,
		Modified: time.Unix(0, 0).UTC(),
	}
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return fmt.Errorf("zip header %s: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("zip write %s: %w", name, err)
	}
	return nil
}

func liveKitReadme(osName VerifyKitOS) string {
	switch osName {
	case VerifyKitOSWindows:
		return "Pipelock - verify your live session (Windows)\r\n\r\nDouble-click Verify.bat.\r\nA valid run prints result: VALID. Nothing here touches the internet.\r\n"
	case VerifyKitOSMacOS:
		return "Pipelock - verify your live session (macOS)\n\nThe verifier is a universal Intel/Apple Silicon binary, but it is not Apple-notarized, so macOS Gatekeeper may block a freshly downloaded copy. If double-clicking Verify.command is blocked, open Terminal in this folder and run:\n\n  xattr -d com.apple.quarantine Verify.command app/pipelock-verifier\n  ./Verify.command\n\nA valid run prints result: VALID. Nothing here touches the internet. Notarized macOS support is planned; Linux and Windows need no extra step.\n"
	default:
		return "Pipelock - verify your live session (Linux)\n\nOpen a terminal in this folder and run:\n\n  ./verify.sh\n\nDouble-clicking usually opens it in a text editor instead of running it - that is normal on Linux; use the terminal.\nA valid run prints result: VALID. Nothing here touches the internet.\n"
	}
}

func liveKitScript(osName VerifyKitOS, orchKey string) (string, string, error) {
	switch osName {
	case VerifyKitOSWindows:
		return "Verify.bat", "@echo off\r\ncd /d \"%~dp0app\"\r\necho Verifying the full Pipelock playground trust chain, offline...\r\necho.\r\npipelock-verifier.exe verify-run run --orchestrator-key " + orchKey + "\r\necho.\r\necho result: VALID means every signature, the receipt chain, witnesses, and run binding held.\r\necho No network was used.\r\necho.\r\npause\r\n", nil
	case VerifyKitOSMacOS:
		return "Verify.command", "#!/bin/bash\ncd \"$(dirname \"$0\")/app\"\necho \"Verifying the full Pipelock playground trust chain, offline...\"\necho\n./pipelock-verifier verify-run run --orchestrator-key " + orchKey + "\necho\necho \"result: VALID means every signature, the receipt chain, witnesses, and run binding held.\"\necho \"No network was used.\"\nread -n 1 -s -r -p \"Press any key to close.\"\n", nil
	case VerifyKitOSLinux:
		return "verify.sh", "#!/bin/bash\ncd \"$(dirname \"$0\")/app\"\necho \"Verifying the full Pipelock playground trust chain, offline...\"\necho\n./pipelock-verifier verify-run run --orchestrator-key " + orchKey + "\necho\necho \"result: VALID means every signature, the receipt chain, witnesses, and run binding held.\"\necho \"No network was used.\"\n", nil
	default:
		return "", "", fmt.Errorf("unsupported verify kit OS %q", osName)
	}
}

func liveKitVerifierTxt(orchKey string) string {
	return fmt.Sprintf(`Pipelock live session - full trust chain verification
trust_root: %s (published Pipelock Playground orchestrator key)
verdict: run pipelock-verifier verify-run run --orchestrator-key %s

Verify it yourself from this directory:
  pipelock-verifier verify-run run --orchestrator-key %s

This performs the full verification chain:
  - Launch manifest signature (orchestrator key)
  - Audit packet receipt chain (manifest-pinned pipelock key)
  - Collector witness signature and run binding
  - Red-case calibration
  - Host-containment witness (if contained)
`, orchKey, orchKey, orchKey)
}
