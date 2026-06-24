// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
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

// BuildLiveVerifyKit builds a single-download, offline verification kit for one
// sealed live session. sessionTarGz must be the output of ArchiveRunForDownload.
// The kit embeds the real verifier binary and the session's audit packet.
func BuildLiveVerifyKit(osName VerifyKitOS, verifierPath string, sessionTarGz []byte, fallbackTrustKey string) ([]byte, string, error) {
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
	trustKey, err := validateLiveKitTrustKey(liveKitTrustKey(files, fallbackTrustKey))
	if err != nil {
		return nil, "", err
	}

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

	for _, name := range []string{"packet/packet.json", "packet/manifest.json", "packet/evidence.jsonl"} {
		data, ok := files[name]
		if !ok {
			return nil, "", fmt.Errorf("session bundle missing %s", name)
		}
		if err := zipFile(zw, root+"/app/"+name, data, 0o600); err != nil {
			return nil, "", err
		}
	}
	if verify, ok := files["VERIFY.txt"]; ok {
		if err := zipFile(zw, root+"/app/SESSION-VERIFY.txt", verify, 0o600); err != nil {
			return nil, "", err
		}
	}
	if err := zipFile(zw, root+"/app/packet/verifier.txt", []byte(liveKitVerifierTxt(trustKey)), 0o600); err != nil {
		return nil, "", err
	}

	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("close verify kit zip: %w", err)
	}
	return buf.Bytes(), "pipelock-live-verify-" + string(osName) + ".zip", nil
}

func liveKitTrustKey(files map[string][]byte, fallback string) string {
	var packet struct {
		Verifier struct {
			SignerKey string `json:"signer_key"`
		} `json:"verifier"`
	}
	if data := files["packet/packet.json"]; len(data) > 0 {
		if err := json.Unmarshal(data, &packet); err == nil && strings.TrimSpace(packet.Verifier.SignerKey) != "" {
			return strings.TrimSpace(packet.Verifier.SignerKey)
		}
	}
	var manifest struct {
		SignerKey string `json:"signer_key"`
	}
	if data := files["packet/manifest.json"]; len(data) > 0 {
		if err := json.Unmarshal(data, &manifest); err == nil && strings.TrimSpace(manifest.SignerKey) != "" {
			return strings.TrimSpace(manifest.SignerKey)
		}
	}
	return fallback
}

func validateLiveKitTrustKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("verify kit trust key is not hex: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("verify kit trust key length = %d bytes, want 32", len(decoded))
	}
	return key, nil
}

func extractLiveKitFiles(sessionTarGz []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(sessionTarGz))
	if err != nil {
		return nil, fmt.Errorf("read session bundle gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

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
		switch name {
		case "VERIFY.txt", "packet/packet.json", "packet/manifest.json", "packet/evidence.jsonl":
		default:
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
		return "Pipelock - verify your live session (Linux)\n\nRun ./verify.sh, or double-click it if your file manager runs scripts.\nA valid run prints result: VALID. Nothing here touches the internet.\n"
	}
}

func liveKitScript(osName VerifyKitOS, key string) (string, string, error) {
	switch osName {
	case VerifyKitOSWindows:
		return "Verify.bat", "@echo off\r\ncd /d \"%~dp0app\"\r\necho Verifying the signed Pipelock audit packet, offline...\r\necho.\r\npipelock-verifier.exe audit-packet packet --key " + key + "\r\necho.\r\necho result: VALID means every signature and the hash chain held. No network was used.\r\necho.\r\npause\r\n", nil
	case VerifyKitOSMacOS:
		return "Verify.command", "#!/bin/bash\ncd \"$(dirname \"$0\")/app\"\necho \"Verifying the signed Pipelock audit packet, offline...\"\necho\n./pipelock-verifier audit-packet packet --key " + key + "\necho\necho \"result: VALID means every signature and the hash chain held. No network was used.\"\nread -n 1 -s -r -p \"Press any key to close.\"\n", nil
	case VerifyKitOSLinux:
		return "verify.sh", "#!/bin/bash\ncd \"$(dirname \"$0\")/app\"\necho \"Verifying the signed Pipelock audit packet, offline...\"\n./pipelock-verifier audit-packet packet --key " + key + "\n", nil
	default:
		return "", "", fmt.Errorf("unsupported verify kit OS %q", osName)
	}
}

func liveKitVerifierTxt(key string) string {
	return fmt.Sprintf(`Pipelock live session audit packet
verdict: run pipelock-verifier audit-packet packet --key %s
signer_key: %s

Verify it yourself from this directory:
  pipelock-verifier audit-packet packet --key %s
`, key, key, key)
}
