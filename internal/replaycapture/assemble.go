// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// Safe, synthetic constants stamped into the (unsigned) Audit Packet envelope.
// None reveal real infrastructure: the run is a local synthetic lab, the agent
// identity names the lab, and posture is honestly "unknown" for probes the rig
// does not run (launch gate #8: no fake CI-like claims).
const (
	labAgentIdentity       = "pipelock-lab-agent"
	enforcementModeLab     = "synthetic_lab"
	runnerOSLab            = "linux"
	artifactPacketName     = "packet.json"
	artifactEvidenceName   = "evidence.jsonl"
	artifactVerifierName   = "verifier.txt"
	artifactSummaryName    = "summary.md"
	filePerm               = 0o600
	dirPerm                = 0o750
	rfc3339                = time.RFC3339
	packetIDPrefix         = "ap-"
	verifierVerdictTrusted = auditpacket.VerdictValid
)

// errEnvelope wraps every packet-envelope safety rejection.
var errEnvelope = errors.New("packet envelope safety violation")

// AssembleResult is the output of assembling one scenario's Audit Packet.
type AssembleResult struct {
	Scenario  Scenario
	Packet    *auditpacket.Packet
	PacketDir string
	Receipts  int
}

// AssemblePacket gates a captured scenario through the public-safe allowlist,
// builds an Audit Packet v0 from safe constants and the real receipt chain,
// validates it (schema + envelope safety), and writes the packet directory
// (packet.json, evidence.jsonl, verifier.txt, summary.md). generatedAt is
// injected so callers control the stamp (and tests stay deterministic).
func AssemblePacket(cs *CapturedScenario, outDir string, generatedAt time.Time) (*AssembleResult, error) {
	if cs == nil {
		return nil, errors.New("assemble: nil captured scenario")
	}
	if len(cs.Receipts) == 0 {
		return nil, fmt.Errorf("assemble %s: no receipts", cs.Scenario.ID)
	}

	// Gate: every receipt must pass the public-safe allowlist BEFORE assembly.
	for i := range cs.Receipts {
		if err := ValidateReceiptPublicSafe(cs.Receipts[i].ActionRecord); err != nil {
			return nil, fmt.Errorf("assemble %s: receipt %d: %w", cs.Scenario.ID, i, err)
		}
	}

	pkt := buildPacket(cs, generatedAt)

	if err := pkt.Validate(); err != nil {
		return nil, fmt.Errorf("assemble %s: packet schema: %w", cs.Scenario.ID, err)
	}
	if err := ValidatePacketEnvelopePublicSafe(pkt); err != nil {
		return nil, fmt.Errorf("assemble %s: %w", cs.Scenario.ID, err)
	}

	packetDir := filepath.Join(outDir, cs.Scenario.ID)
	if err := os.MkdirAll(packetDir, dirPerm); err != nil {
		return nil, fmt.Errorf("assemble %s: mkdir: %w", cs.Scenario.ID, err)
	}
	if err := writePacketFiles(packetDir, cs, pkt); err != nil {
		return nil, fmt.Errorf("assemble %s: %w", cs.Scenario.ID, err)
	}

	return &AssembleResult{
		Scenario:  cs.Scenario,
		Packet:    pkt,
		PacketDir: packetDir,
		Receipts:  len(cs.Receipts),
	}, nil
}

// buildPacket constructs the Audit Packet v0 envelope from safe constants plus
// the computed summary of the real receipt chain.
func buildPacket(cs *CapturedScenario, generatedAt time.Time) *auditpacket.Packet {
	summary := summarize(cs.Receipts)
	first := cs.Receipts[0].ActionRecord
	last := cs.Receipts[len(cs.Receipts)-1].ActionRecord

	return &auditpacket.Packet{
		SchemaVersion: auditpacket.SchemaVersion,
		PacketID:      packetIDPrefix + cs.Scenario.ID,
		GeneratedAt:   generatedAt.UTC().Format(rfc3339),
		Run: auditpacket.Run{
			Provider:      auditpacket.ProviderLocal,
			AgentIdentity: labAgentIdentity,
			StartedAt:     first.Timestamp.UTC().Format(rfc3339),
			CompletedAt:   last.Timestamp.UTC().Format(rfc3339),
		},
		Policy: auditpacket.Policy{
			PolicyHashes: []string{cs.PolicyHash},
		},
		Summary: summary,
		Verifier: auditpacket.Verifier{
			Verdict:      verifierVerdictTrusted,
			Trusted:      true,
			ReceiptCount: cs.ReceiptCount,
			RootHash:     cs.RootHash,
			FinalSeq:     boundedInt(cs.FinalSeq),
			SignerKey:    cs.SignerKeyHex,
			OutputFile:   artifactVerifierName,
		},
		Posture: auditpacket.Posture{
			EnforcementMode:        enforcementModeLab,
			RunnerOS:               runnerOSLab,
			RawSocketStatus:        auditpacket.StatusUnknown,
			DockerSocketStatus:     auditpacket.StatusUnknown,
			DNSUDPStatus:           auditpacket.StatusUnknown,
			BrowserProxyStatus:     auditpacket.StatusUnknown,
			WebsocketFrameScanning: auditpacket.WebsocketFrameScanningOff,
			UnsupportedPaths:       []string{},
		},
		Artifacts: auditpacket.Artifacts{
			Packet:   artifactPacketName,
			Summary:  artifactSummaryName,
			Evidence: artifactEvidenceName,
			Verifier: artifactVerifierName,
		},
	}
}

// summarize computes the packet summary (totals, transports, layers,
// domains_touched) from the real receipt chain so the verifier cross-check
// reconciles.
func summarize(receipts []receipt.Receipt) auditpacket.Summary {
	var totals auditpacket.Totals
	transports := map[string]int{}
	layers := map[string]int{}
	var hosts []string

	for _, r := range receipts {
		ar := r.ActionRecord
		addVerdict(&totals, ar.Verdict)
		if ar.Transport != "" {
			transports[ar.Transport]++
		}
		if ar.Layer != "" {
			layers[ar.Layer]++
		}
		if h := hostOf(ar.Target); h != "" {
			hosts = append(hosts, h)
		}
	}

	return auditpacket.Summary{
		ReceiptCount:   len(receipts),
		Totals:         totals,
		Transports:     transports,
		Layers:         layers,
		DomainsTouched: auditpacket.SortedDomains(hosts),
	}
}

// addVerdict increments the matching totals bucket; unknown verdicts fall to
// "other" so the eight buckets always sum to the receipt count.
func addVerdict(t *auditpacket.Totals, verdict string) {
	switch verdict {
	case verdictAllow:
		t.Allow++
	case verdictBlock:
		t.Block++
	case verdictWarn:
		t.Warn++
	case "ask":
		t.Ask++
	case "strip":
		t.Strip++
	case "forward":
		t.Forward++
	case "redirect":
		t.Redirect++
	default:
		t.Other++
	}
}

// hostOf returns the hostname of a receipt target, or empty on parse failure.
func hostOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ValidatePacketEnvelopePublicSafe enforces that the (unsigned) Audit Packet
// envelope carries no field the receipt sanitizer does not touch and that could
// reveal real infrastructure: repo/run identity, config/runtime paths, host or
// agent IPs, proxy URL, script basename, network namespace, or a non-synthetic
// touched domain. Fail-closed.
func ValidatePacketEnvelopePublicSafe(pkt *auditpacket.Packet) error {
	if pkt == nil {
		return fmt.Errorf("%w: nil packet", errEnvelope)
	}
	if pkt.Run.Provider != auditpacket.ProviderLocal {
		return fmt.Errorf("%w: run.provider %q must be local", errEnvelope, pkt.Run.Provider)
	}
	if pkt.Run.AgentIdentity != labAgentIdentity {
		return fmt.Errorf("%w: run.agent_identity %q is not the lab identity", errEnvelope, pkt.Run.AgentIdentity)
	}
	runForbidden := map[string]string{
		"run.repository":  pkt.Run.Repository,
		"run.workflow":    pkt.Run.Workflow,
		"run.run_id":      pkt.Run.RunID,
		"run.run_attempt": pkt.Run.RunAttempt,
		"run.ref":         pkt.Run.Ref,
		"run.sha":         pkt.Run.SHA,
	}
	policyForbidden := map[string]string{
		"policy.config_path":            pkt.Policy.ConfigPath,
		"policy.runtime_config_path":    pkt.Policy.RuntimeConfigPath,
		"policy.config_snapshot_sha256": pkt.Policy.ConfigSnapshotSHA256,
	}
	postureForbidden := map[string]string{
		"posture.host_ip":           pkt.Posture.HostIP,
		"posture.agent_ip":          pkt.Posture.AgentIP,
		"posture.proxy_url":         pkt.Posture.ProxyURL,
		"posture.script_basename":   pkt.Posture.ScriptBasename,
		"posture.network_namespace": pkt.Posture.NetworkNamespace,
		"posture.agent_user":        pkt.Posture.AgentUser,
		"posture.host_user":         pkt.Posture.HostUser,
	}
	for _, group := range []map[string]string{runForbidden, policyForbidden, postureForbidden} {
		for field, val := range group {
			if val != "" {
				return fmt.Errorf("%w: %s must be empty, got %q", errEnvelope, field, val)
			}
		}
	}
	if pkt.Verifier.SignerKey == "" {
		return fmt.Errorf("%w: verifier.signer_key is required to pin the gallery", errEnvelope)
	}
	// Every touched domain must be a synthetic/reserved/lab-local host.
	for _, host := range pkt.Summary.DomainsTouched {
		if err := validateSafeHost(host); err != nil {
			return fmt.Errorf("%w: domains_touched: %w", errEnvelope, err)
		}
	}
	return nil
}

// validateSafeHost applies the receipt target host rules to a bare hostname or
// IP literal (no scheme), used for summary.domains_touched.
func validateSafeHost(host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", errEnvelope)
	}
	return validateSafeTarget("http://" + host)
}

// writePacketFiles writes packet.json, evidence.jsonl (the signed chain),
// verifier.txt, and summary.md into the packet directory.
func writePacketFiles(packetDir string, cs *CapturedScenario, pkt *auditpacket.Packet) error {
	evidenceBytes, err := os.ReadFile(filepath.Clean(cs.EvidenceFile))
	if err != nil {
		return fmt.Errorf("reading evidence: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packetDir, artifactEvidenceName), evidenceBytes, filePerm); err != nil {
		return fmt.Errorf("writing evidence: %w", err)
	}

	packetJSON, err := marshalIndentNoEscape(pkt)
	if err != nil {
		return fmt.Errorf("marshaling packet: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packetDir, artifactPacketName), packetJSON, filePerm); err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}

	if err := os.WriteFile(filepath.Join(packetDir, artifactVerifierName), []byte(verifierText(cs)), filePerm); err != nil {
		return fmt.Errorf("writing verifier: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packetDir, artifactSummaryName), []byte(summaryMarkdown(cs)), filePerm); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}
	return nil
}
