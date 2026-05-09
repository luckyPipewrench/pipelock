// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package auditpacket

import (
	"errors"
	"fmt"
	"sort"
)

// SchemaVersion is the locked identifier producers stamp into every v0 packet.
// Consumers MUST reject packets whose schema_version does not match exactly.
const SchemaVersion = "pipelock.audit_packet.v0"

// Verifier verdict values. Producers MUST emit exactly one of these.
const (
	VerdictValid              = "valid"
	VerdictInvalid            = "invalid"
	VerdictError              = "error"
	VerdictNotRun             = "not_run"
	VerdictSelfConsistentOnly = "self_consistent_only"
)

// Run provider values for github_actions, self_hosted, and local. Other
// providers extend the enum in a future schema version, not v0.
const (
	ProviderGitHubActions = "github_actions"
	ProviderSelfHosted    = "self_hosted"
	ProviderLocal         = "local"
)

// Posture status enum values shared across the four status fields.
const (
	StatusUnknown = "unknown"

	// StatusDenied / StatusAllowed apply to raw_socket_status and dns_udp_status.
	StatusDenied  = "denied"
	StatusAllowed = "allowed"

	// StatusMasked / StatusAbsent apply to docker_socket_status only.
	StatusMasked = "masked"
	StatusAbsent = "absent"

	// StatusProxied applies to dns_udp_status and browser_proxy_status.
	StatusProxied = "proxied"

	// StatusForced / StatusAdvisory apply to browser_proxy_status only.
	StatusForced   = "forced"
	StatusAdvisory = "advisory"
)

// totalsKeys is the locked v0 set. All eight keys MUST be present in
// summary.totals, even when zero.
var totalsKeys = []string{
	"allow",
	"block",
	"warn",
	"ask",
	"strip",
	"forward",
	"redirect",
	"other",
}

// validVerdicts mirrors the verifier.verdict enum in v0.json.
var validVerdicts = map[string]struct{}{
	VerdictValid:              {},
	VerdictInvalid:            {},
	VerdictError:              {},
	VerdictNotRun:             {},
	VerdictSelfConsistentOnly: {},
}

var validProviders = map[string]struct{}{
	ProviderGitHubActions: {},
	ProviderSelfHosted:    {},
	ProviderLocal:         {},
}

// Packet is the top-level audit packet structure. Field tags match the JSON
// field names in v0.json exactly.
type Packet struct {
	SchemaVersion         string                 `json:"schema_version"`
	PacketID              string                 `json:"packet_id,omitempty"`
	GeneratedAt           string                 `json:"generated_at"`
	Run                   Run                    `json:"run"`
	Policy                Policy                 `json:"policy"`
	Summary               Summary                `json:"summary"`
	Verifier              Verifier               `json:"verifier"`
	Receipts              []Receipt              `json:"receipts,omitempty"`
	ScannerConfigSnapshot *ScannerConfigSnapshot `json:"scanner_config_snapshot,omitempty"`
	Posture               Posture                `json:"posture"`
	Artifacts             Artifacts              `json:"artifacts"`
}

// Run captures provider, repo, and agent identity for the run that produced
// the receipts.
type Run struct {
	Provider      string `json:"provider"`
	Repository    string `json:"repository,omitempty"`
	Workflow      string `json:"workflow,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	RunAttempt    string `json:"run_attempt,omitempty"`
	Ref           string `json:"ref,omitempty"`
	SHA           string `json:"sha,omitempty"`
	AgentIdentity string `json:"agent_identity"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at,omitempty"`
	AgentExitCode *int   `json:"agent_exit_code,omitempty"`
}

// Policy captures the pipelock policy state observed during the run.
// PolicyHashes is plural because hot-reload across the run can produce
// multiple distinct hashes.
type Policy struct {
	PolicyHashes         []string `json:"policy_hashes"`
	ConfigPath           string   `json:"config_path,omitempty"`
	RuntimeConfigPath    string   `json:"runtime_config_path,omitempty"`
	ConfigSnapshotSHA256 string   `json:"config_snapshot_sha256,omitempty"`
}

// Summary aggregates counts derived from the receipt chain.
type Summary struct {
	ReceiptCount   int            `json:"receipt_count"`
	Totals         Totals         `json:"totals"`
	Transports     map[string]int `json:"transports,omitempty"`
	Layers         map[string]int `json:"layers,omitempty"`
	DomainsTouched []string       `json:"domains_touched,omitempty"`
}

// Totals carries the eight verdict buckets. All eight MUST be emitted, even
// when zero, so consumers can sum without nil-checks.
type Totals struct {
	Allow    int `json:"allow"`
	Block    int `json:"block"`
	Warn     int `json:"warn"`
	Ask      int `json:"ask"`
	Strip    int `json:"strip"`
	Forward  int `json:"forward"`
	Redirect int `json:"redirect"`
	Other    int `json:"other"`
}

// Verifier carries the verdict from the receipt chain verifier.
type Verifier struct {
	Verdict      string `json:"verdict"`
	Trusted      bool   `json:"trusted"`
	ReceiptCount int    `json:"receipt_count,omitempty"`
	RootHash     string `json:"root_hash,omitempty"`
	FinalSeq     int    `json:"final_seq,omitempty"`
	SignerKey    string `json:"signer_key,omitempty"`
	OutputFile   string `json:"output_file,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Receipt is the inline form of a receipt entry. Consumers SHOULD prefer
// reading evidence.jsonl directly because that is the byte-for-byte signed
// input to the verifier.
type Receipt struct {
	ActionID       string `json:"action_id"`
	ReceiptHash    string `json:"receipt_hash"`
	ChainSeq       int    `json:"chain_seq"`
	ChainPrevHash  string `json:"chain_prev_hash"`
	Timestamp      string `json:"timestamp,omitempty"`
	ActionType     string `json:"action_type,omitempty"`
	Verdict        string `json:"verdict"`
	Transport      string `json:"transport,omitempty"`
	Method         string `json:"method,omitempty"`
	TargetRedacted string `json:"target_redacted,omitempty"`
	Layer          string `json:"layer,omitempty"`
	Pattern        string `json:"pattern,omitempty"`
	Severity       string `json:"severity,omitempty"`
	PolicyHash     string `json:"policy_hash"`
	SignerKey      string `json:"signer_key,omitempty"`
}

// ScannerConfigSnapshot is the optional summary of the pipelock config that
// produced the receipts.
type ScannerConfigSnapshot struct {
	Mode                  string `json:"mode,omitempty"`
	DLPPatternsCount      int    `json:"dlp_patterns_count,omitempty"`
	ResponsePatternsCount int    `json:"response_patterns_count,omitempty"`
	SSRFEnabled           *bool  `json:"ssrf_enabled,omitempty"`
	RedactionEnabled      *bool  `json:"redaction_enabled,omitempty"`
	FlightRecorderEnabled *bool  `json:"flight_recorder_enabled,omitempty"`
}

// Posture documents the enforcement posture claimed by the producer.
type Posture struct {
	EnforcementMode        string   `json:"enforcement_mode"`
	RunnerOS               string   `json:"runner_os"`
	RunnerArch             string   `json:"runner_arch,omitempty"`
	RawSocketStatus        string   `json:"raw_socket_status,omitempty"`
	DockerSocketStatus     string   `json:"docker_socket_status,omitempty"`
	DNSUDPStatus           string   `json:"dns_udp_status,omitempty"`
	BrowserProxyStatus     string   `json:"browser_proxy_status,omitempty"`
	WebsocketFrameScanning string   `json:"websocket_frame_scanning,omitempty"`
	NetworkNamespace       string   `json:"network_namespace,omitempty"`
	AgentUser              string   `json:"agent_user,omitempty"`
	AgentUID               int      `json:"agent_uid,omitempty"`
	HostUser               string   `json:"host_user,omitempty"`
	HostUID                int      `json:"host_uid,omitempty"`
	HostIP                 string   `json:"host_ip,omitempty"`
	AgentIP                string   `json:"agent_ip,omitempty"`
	ProxyURL               string   `json:"proxy_url,omitempty"`
	ScriptBasename         string   `json:"script_basename,omitempty"`
	ScriptArgCount         int      `json:"script_arg_count,omitempty"`
	UnsupportedPaths       []string `json:"unsupported_paths,omitempty"`
}

// Artifacts records relative paths to sibling files in the audit packet
// directory.
type Artifacts struct {
	Packet   string `json:"packet"`
	Summary  string `json:"summary,omitempty"`
	Evidence string `json:"evidence"`
	Verifier string `json:"verifier"`
}

// Validate enforces the structural invariants the JSON Schema also enforces.
// It is intended as a defense-in-depth check for Go callers; producers in
// other languages MUST also pass v0.json validation.
func (p *Packet) Validate() error {
	if p == nil {
		return errors.New("auditpacket: nil packet")
	}
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("auditpacket: schema_version %q is not %q", p.SchemaVersion, SchemaVersion)
	}
	if p.GeneratedAt == "" {
		return errors.New("auditpacket: generated_at is required")
	}
	if err := p.Run.validate(); err != nil {
		return fmt.Errorf("auditpacket: run: %w", err)
	}
	if err := p.Policy.validate(); err != nil {
		return fmt.Errorf("auditpacket: policy: %w", err)
	}
	if err := p.Summary.validate(); err != nil {
		return fmt.Errorf("auditpacket: summary: %w", err)
	}
	if err := p.Verifier.validate(); err != nil {
		return fmt.Errorf("auditpacket: verifier: %w", err)
	}
	if err := p.Posture.validate(); err != nil {
		return fmt.Errorf("auditpacket: posture: %w", err)
	}
	if err := p.Artifacts.validate(); err != nil {
		return fmt.Errorf("auditpacket: artifacts: %w", err)
	}
	return nil
}

func (r Run) validate() error {
	if _, ok := validProviders[r.Provider]; !ok {
		return fmt.Errorf("provider %q not in {github_actions, self_hosted, local}", r.Provider)
	}
	if r.AgentIdentity == "" {
		return errors.New("agent_identity is required")
	}
	if r.StartedAt == "" {
		return errors.New("started_at is required")
	}
	return nil
}

func (p Policy) validate() error {
	if p.PolicyHashes == nil {
		return errors.New("policy_hashes is required (use empty array, not null)")
	}
	return nil
}

func (s Summary) validate() error {
	if s.ReceiptCount < 0 {
		return errors.New("receipt_count must be non-negative")
	}
	// Confirm computed sum across the eight buckets is non-negative; per-field
	// negative counts are caught by the JSON Schema and would also fail here
	// when the caller hand-builds a Totals.
	if s.Totals.Allow < 0 || s.Totals.Block < 0 || s.Totals.Warn < 0 ||
		s.Totals.Ask < 0 || s.Totals.Strip < 0 || s.Totals.Forward < 0 ||
		s.Totals.Redirect < 0 || s.Totals.Other < 0 {
		return errors.New("totals counts must be non-negative")
	}
	return nil
}

func (v Verifier) validate() error {
	if _, ok := validVerdicts[v.Verdict]; !ok {
		return fmt.Errorf("verdict %q not in {valid, invalid, error, not_run, self_consistent_only}", v.Verdict)
	}
	// Consumers must not conflate self_consistent_only with valid; the schema
	// makes this hard to misconfigure, but enforce here too.
	if v.Trusted && v.Verdict != VerdictValid {
		return fmt.Errorf("trusted=true requires verdict=valid, got %q", v.Verdict)
	}
	return nil
}

func (p Posture) validate() error {
	if p.EnforcementMode == "" {
		return errors.New("enforcement_mode is required")
	}
	if p.RunnerOS == "" {
		return errors.New("runner_os is required")
	}
	return nil
}

func (a Artifacts) validate() error {
	if a.Packet == "" {
		return errors.New("packet path is required")
	}
	if a.Evidence == "" {
		return errors.New("evidence path is required")
	}
	if a.Verifier == "" {
		return errors.New("verifier path is required")
	}
	return nil
}

// TotalsKeys returns the locked v0 totals key list. Producers iterating to
// emit zero buckets SHOULD walk this list so they cannot accidentally drop
// a key during a refactor.
func TotalsKeys() []string {
	out := make([]string, len(totalsKeys))
	copy(out, totalsKeys)
	return out
}

// SortedDomains returns a sorted unique copy of the input domain list.
// Producers SHOULD use it before stamping summary.domains_touched so two
// runs with the same hosts in different observation order produce
// byte-identical packets.
func SortedDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
