// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package scanner provides URL scanning for the Pipelock fetch proxy.
// It checks URLs against blocklists, DLP patterns, and entropy thresholds
// before allowing the fetch proxy to retrieve them.
package scanner

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
	"github.com/luckyPipewrench/pipelock/internal/seedprotect"
)

// Scanner label constants. These values flow into Prometheus metrics
// (pipelock_scanner_hits_total{scanner="..."}), suppression rules, and audit
// logs. Changing a value is a breaking change for dashboards and alerts.
const (
	ScannerParser           = "parser"
	ScannerScheme           = "scheme"
	ScannerLength           = "length"
	ScannerSSRF             = "ssrf"
	ScannerSSRFMetadata     = "ssrf_metadata"
	ScannerAllowlist        = "allowlist"
	ScannerBlocklist        = "blocklist"
	ScannerRateLimit        = "ratelimit"
	ScannerDLP              = "dlp"
	ScannerEntropy          = "entropy"
	ScannerSubdomainEntropy = "subdomain_entropy"
	ScannerDataBudget       = "databudget"
	ScannerPathTraversal    = "path_traversal"
	ScannerCRLF             = "crlf_injection"
	ScannerContext          = "context"
	ScannerAll              = "all"
)

// ResultClass distinguishes protective enforcement (rate limiting) from threat
// evidence (DLP matches, injection, SSRF, data budget exhaustion). The proxy's
// adaptive enforcement uses this to avoid penalising agents for protective blocks.
type ResultClass int

const (
	// ClassThreat is the zero value: the block indicates a genuine threat
	// signal (DLP match, injection, blocklist hit, etc.).
	ClassThreat ResultClass = iota
	// ClassProtective means the block is protective enforcement (rate
	// limiting, data budget) - not evidence of malicious intent.
	ClassProtective
	// ClassConfigMismatch means the block is due to a configuration gap
	// (e.g., domain in api_allowlist but not trusted_domains). Not a
	// real attack - should not feed adaptive escalation.
	ClassConfigMismatch
	// ClassInfrastructureError means the block is due to an infrastructure
	// failure (e.g., DNS resolver timeout, resolver unreachable) rather
	// than adversarial behavior. Fail-closed semantics are preserved
	// (the request is still blocked), but the block must not feed
	// adaptive enforcement: resolver instability is not threat evidence.
	// A burst of DNS failures would otherwise cascade into airlock lockdown
	// via SignalBlock accumulation.
	ClassInfrastructureError
	// ClassStructuralExemption means the request was allowed because a
	// would-be DLP match sits inside a structurally validated capability
	// token (e.g., the AKIA inside a SigV4 X-Amz-Credential value of a
	// presigned URL). The matched value is a scoped bearer for a specific
	// resource, not a leaked long-lived credential. Adaptive-neutral: a
	// burst of legitimate presigned-URL fetches must not poison the
	// session score, but should also not earn clean-decay trust.
	ClassStructuralExemption
)

// WarnMatch describes a DLP pattern match from a warn-mode pattern.
// These are informational only - they do not block or alter the request.
type WarnMatch struct {
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	span        MatchSpan
}

// Span returns retained coordinates for this warn-mode DLP match.
func (m WarnMatch) Span() MatchSpan {
	return m.span
}

// DNSErrorKind tags the specific DNS resolver failure mode that produced a
// ClassInfrastructureError result. The kind drives audit-time display labels
// and metric subdivision but never changes the verdict: every DNS failure
// still fails closed. Empty when the Result was not produced by the DNS
// resolution path.
type DNSErrorKind string

const (
	// DNSErrorTimeout reports an i/o timeout from the resolver. The resolver
	// produced no answer, so the proxy has no information about whether the
	// target would resolve to an internal address. Classifying as ssrf would
	// assert a finding the scanner cannot support.
	DNSErrorTimeout DNSErrorKind = "timeout"
	// DNSErrorNoSuchHost reports an authoritative NXDOMAIN or no-records
	// answer. The resolver answered; the absence is informative but is not a
	// signal of an SSRF probe.
	DNSErrorNoSuchHost DNSErrorKind = "no_such_host"
	// DNSErrorResolver covers other resolver-side failures (refused, format
	// error, server failure) that produce no usable IP. Kept distinct from
	// timeout because operator alerting may want different treatment.
	DNSErrorResolver DNSErrorKind = "resolver_error"
)

// Result describes the outcome of scanning a URL.
type Result struct {
	Allowed      bool         `json:"allowed"`
	Reason       string       `json:"reason,omitempty"`
	Scanner      string       `json:"scanner,omitempty"` // which scanner triggered
	Hint         string       `json:"hint,omitempty"`    // actionable guidance when blocked
	Score        float64      `json:"score"`             // anomaly score 0.0-1.0
	Class        ResultClass  `json:"-"`                 // internal: threat vs protective classification
	DNSErrorKind DNSErrorKind `json:"-"`                 // internal: DNS resolver failure subtype (set only when Class == ClassInfrastructureError on the DNS path)
	WarnMatches  []WarnMatch  `json:"warn_matches,omitempty"`
	spans        []MatchSpan
}

// Spans returns retained scanner match coordinates for this result.
// The returned slice is caller-owned and never includes matched bytes.
func (r Result) Spans() []MatchSpan {
	return copySpans(r.spans)
}

// IsProtective reports whether this result represents protective enforcement
// (e.g., rate limiting) rather than a threat detection.
func (r Result) IsProtective() bool {
	return r.Class == ClassProtective
}

// IsConfigMismatch reports whether this result represents a configuration
// gap rather than a real threat (e.g., SSRF blocking an allowlisted domain).
func (r Result) IsConfigMismatch() bool {
	return r.Class == ClassConfigMismatch
}

// IsInfrastructureError reports whether this result represents an
// infrastructure failure (e.g., DNS resolver timeout, resolver unreachable)
// rather than a threat. Blocks with this class preserve fail-closed semantics
// but must not feed adaptive enforcement scoring.
func (r Result) IsInfrastructureError() bool {
	return r.Class == ClassInfrastructureError
}

// IsStructuralExemption reports whether this allow result represents a
// structurally validated capability-token carve-out (e.g., the AKIA inside
// a SigV4 X-Amz-Credential of a presigned URL). The match was real but
// scoped to a single resource by the issuer; treating it as a clean signal
// would let an attacker drive adaptive score down via legitimate fetches,
// so it is adaptive-neutral instead.
func (r Result) IsStructuralExemption() bool {
	return r.Class == ClassStructuralExemption
}

// IsAdaptiveNeutral reports whether this result should be score-neutral for
// adaptive enforcement: protective enforcement (rate limiting, data budget),
// infrastructure failures (DNS resolver errors), and structural exemptions
// (validated capability tokens) all skip both block-signal and clean-decay.
// Config mismatch is NOT covered here - it produces a bounded SignalNearMiss
// by design so repeated probing of misconfigured allowlists remains visible
// to scoring.
func (r Result) IsAdaptiveNeutral() bool {
	return r.IsProtective() || r.IsInfrastructureError() || r.IsStructuralExemption()
}

// IsHostnameExfilResult reports whether a URL scan result came from a
// structural hostname-exfiltration signal rather than generic subdomain
// entropy. Transports use this to preserve hard-block semantics in warn mode.
func IsHostnameExfilResult(r Result) bool {
	return r.Scanner == ScannerSubdomainEntropy &&
		(strings.HasPrefix(r.Reason, subdomainEncodedLabelReasonPrefix) ||
			strings.HasPrefix(r.Reason, subdomainEncodedChunksReasonPrefix))
}

// dlpWarnCtxKey and DLPWarnContext are defined in warnctx.go.

// Scanner checks URLs for suspicious content before fetching.
type Scanner struct {
	core                       *compiledCoreScanner // immutable safety floor - always runs, no config knobs
	allowlist                  []string
	blocklist                  []string
	dlpPatterns                []*compiledPattern
	canaryTokens               []compiledCanaryToken
	dlpPreFilter               *dlpPreFilter
	entropyThreshold           float64
	subdomainEntropyThreshold  float64
	entropyMinLen              int
	maxURLLength               int
	internalCIDRs              []*net.IPNet
	ipAllowlistCIDRs           []*net.IPNet // SSRF-exempt IP ranges (ssrf.ip_allowlist)
	trustedDomains             []string     // SSRF-exempt domains (wildcard via MatchDomain)
	rawAPIAllowlist            []string     // full api_allowlist for SSRF hint generation (all modes)
	rateLimiter                *RateLimiter
	dataBudget                 *DataBudget
	envSecrets                 []string // filtered high-entropy env var values
	fileSecrets                []string // loaded from secrets_file config
	minEnvSecretLen            int      // minimum env var length for leak detection
	responsePatterns           []*compiledPattern
	responseOptSpacePatterns   []*compiledPattern // \s+ → \s* variants for ZW-stripped pass
	responseVowelFoldPatterns  []*compiledPattern // vowel-folded variants for confusable vowel attacks
	responsePreFilter          *responsePreFilter // keyword candidate gate for primary regex passes
	responseOptSpacePreFilter  *responsePreFilter // keyword candidate gate for opt-space pass
	responseVowelFoldPreFilter *responsePreFilter // keyword candidate gate for vowel-fold pass
	responseAction             string
	responseEnabled            bool
	subdomainExclusions        []string // domains excluded from subdomain entropy checks
	queryExclusions            []string // domains excluded from query parameter entropy checks (S3 pre-signed URLs, etc.)
	queryParamExclusions       map[queryEntropyParamExclusionKey]struct{}
	// pathEntropyExempt suppresses the path-entropy gate on paths the operator
	// already governs with a request_policy route (explicit host + path
	// constraints). A nil or disabled matcher keeps path entropy fully active.
	// Path-only: subdomain and query entropy are never affected by this.
	pathEntropyExempt  *reqpolicy.Matcher
	addressChecker     *addressprotect.Checker
	seedEnabled        bool
	seedMinWords       int
	seedVerifyChecksum bool
	dlpWarnHookMu      sync.RWMutex
	dlpWarnHook        func(ctx context.Context, patternName, severity string)

	// Lifecycle: BeginUse / Close coordination. Once Close starts, BeginUse
	// returns ok=false and callers must re-Load the proxy's scannerPtr to
	// obtain the swapped-in scanner. Close blocks until inUse drains so an
	// in-flight Scan never sees a half-torn-down scanner. Today only ticker
	// goroutines are stopped, but future additions (sqlite handles, file
	// descriptors) make this drain a hard prerequisite for safe reload.
	//
	// drained transitions false→true exactly once at the end of Close,
	// after the rateLimiter and dataBudget have been torn down. closed is
	// set BEFORE drain begins, so Closed() and Drained() are distinct
	// signals: Closed reports "Close was initiated", Drained reports
	// "Close has completed teardown".
	closeMu sync.RWMutex
	closed  bool
	inUse   sync.WaitGroup
	drained atomic.Bool

	// heartbeat is invoked at the end of every Scan() to feed the
	// wedge-detection watchdog. atomic.Pointer keeps SetHeartbeat
	// race-safe even though production wires it before Start.
	heartbeat atomic.Pointer[heartbeatFn]

	// resolver answers SSRF DNS lookups and the proxy dial path. Default is
	// net.DefaultResolver; populated from cfg.DNS.HostOverrides in New().
	// Hostname-only overrides; IP literals bypass via the upstream resolver.
	resolver Resolver
}

// heartbeatFn wraps a func() so it can live behind atomic.Pointer (which
// requires a concrete pointer-to-struct, not a pointer-to-function).
type heartbeatFn struct{ fn func() }

// SetHeartbeat installs a callback invoked after every successful Scan.
// Pass nil to detach. Cheap; safe to call concurrently with Scan because
// the holder is read via atomic.Pointer.
func (s *Scanner) SetHeartbeat(fn func()) {
	if fn == nil {
		s.heartbeat.Store(nil)
		return
	}
	s.heartbeat.Store(&heartbeatFn{fn: fn})
}

// scannerCloseDrainTimeout caps how long Close() waits for in-flight scans
// to drain before forcing teardown of internal resources. Prevents a hung
// upstream from leaking the scanner indefinitely on a hot reload. Override
// only in tests via SetCloseDrainTimeoutForTest.
var scannerCloseDrainTimeout = 30 * time.Second

// SetCloseDrainTimeoutForTest overrides scannerCloseDrainTimeout for the
// duration of a test and returns a restore function. Tests use a short
// timeout to assert the drain-timeout fail-safe without slowing the suite.
// Not safe for parallel tests touching this knob.
func SetCloseDrainTimeoutForTest(d time.Duration) func() {
	prev := scannerCloseDrainTimeout
	scannerCloseDrainTimeout = d
	return func() { scannerCloseDrainTimeout = prev }
}

// SetDLPWarnHook sets the callback for warn-mode DLP matches.
// The hook receives the request context (which may carry DLPWarnContext
// metadata), pattern name, and severity. Called once per scanner instance
// from runtime startup and on config reload.
func (s *Scanner) SetDLPWarnHook(hook func(ctx context.Context, patternName, severity string)) {
	s.dlpWarnHookMu.Lock()
	defer s.dlpWarnHookMu.Unlock()
	s.dlpWarnHook = hook
}

func (s *Scanner) getDLPWarnHook() func(ctx context.Context, patternName, severity string) {
	s.dlpWarnHookMu.RLock()
	defer s.dlpWarnHookMu.RUnlock()
	return s.dlpWarnHook
}

type compiledPattern struct {
	name                string
	re                  *regexp.Regexp
	severity            string
	validate            func(string) bool // post-match checksum (nil = regex-only)
	exemptDomains       []string          // domains where this pattern is skipped (wildcard supported)
	bundle              string            // empty for built-in/config patterns
	bundleVersion       string
	warn                bool // true when pattern action is "warn" - matches are informational only
	requiredLiteralsAny []string
}

// matches returns true if text matches the regex AND passes the post-match
// validator (if any). For patterns without a validator, this uses the faster
// MatchString (no string extraction). For validated patterns (credit cards,
// IBANs), FindAllString extracts ALL matches and returns true if any pass
// checksum - prevents a checksum-failing decoy from suppressing a later
// valid match in the same text blob.
func (p *compiledPattern) matches(text string) bool {
	if p.validate == nil {
		return p.re.MatchString(text)
	}
	// Check all regex hits, not just the first. An attacker could front-load
	// BIN-matching decoys that fail checksum before the real card/IBAN.
	// No cap: regex specificity (BIN prefixes, IBAN format) and data budget
	// limits already bound the match count in practice.
	for _, m := range p.re.FindAllString(text, -1) {
		if p.validate(m) {
			return true
		}
	}
	return false
}

// New creates a Scanner from config. Config must be validated first via
// config.Validate() - this function panics on invalid DLP patterns or CIDRs
// because those represent programming errors (validation should have caught them).
func New(cfg *config.Config) *Scanner {
	// Only enforce the allowlist in strict mode. In balanced/audit modes,
	// the allowlist is a config field but not enforced at the scanner level.
	var allowlist []string
	if cfg.Mode == config.ModeStrict {
		allowlist = cfg.APIAllowlist
	}

	s := &Scanner{
		core:                      initCoreScanner(),
		allowlist:                 allowlist,
		blocklist:                 cfg.FetchProxy.Monitoring.Blocklist,
		entropyThreshold:          cfg.FetchProxy.Monitoring.EntropyThreshold,
		subdomainEntropyThreshold: cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold,
		entropyMinLen:             20,
		maxURLLength:              cfg.FetchProxy.Monitoring.MaxURLLength,
		subdomainExclusions:       cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions,
		queryExclusions:           cfg.FetchProxy.Monitoring.QueryEntropyExclusions,
		queryParamExclusions:      buildQueryEntropyParamExclusions(cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions),
		pathEntropyExempt:         buildPathEntropyExempt(cfg),
	}

	// Initialize rate limiter if enabled
	if cfg.FetchProxy.Monitoring.MaxReqPerMinute > 0 {
		s.rateLimiter = NewRateLimiter(cfg.FetchProxy.Monitoring.MaxReqPerMinute)
	}

	// Compile DLP patterns - must succeed since config.Validate checks these.
	// Force case-insensitive matching: agents can trivially .toUpperCase() a
	// secret before exfiltration, so DLP patterns must match regardless of case.
	for _, p := range cfg.DLP.Patterns {
		pattern := p.Regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Sprintf("BUG: DLP pattern %q failed to compile after validation: %v", p.Name, err))
		}
		cp := &compiledPattern{
			name:          p.Name,
			re:            re,
			severity:      p.Severity,
			exemptDomains: p.ExemptDomains,
			bundle:        p.Bundle,
			bundleVersion: p.BundleVersion,
			warn:          p.Action == config.ActionWarn,
		}
		if p.Validator != "" {
			fn, ok := DLPValidators[p.Validator]
			if !ok {
				panic(fmt.Sprintf("BUG: unknown DLP validator %q for pattern %q", p.Validator, p.Name))
			}
			cp.validate = fn
		}
		s.dlpPatterns = append(s.dlpPatterns, cp)
	}

	// Build prefix pre-filter for fast DLP short-circuiting on clean input.
	s.dlpPreFilter = newDLPPreFilter(s.dlpPatterns)
	s.canaryTokens = compileCanaryTokens(cfg.CanaryTokens)

	// Seed phrase detection config - stateless, reads from config.
	s.seedEnabled = cfg.SeedPhraseDetection.Enabled == nil || *cfg.SeedPhraseDetection.Enabled
	s.seedMinWords = cfg.SeedPhraseDetection.MinWords
	if s.seedMinWords == 0 {
		s.seedMinWords = 12
	}
	s.seedVerifyChecksum = cfg.SeedPhraseDetection.VerifyChecksum == nil || *cfg.SeedPhraseDetection.VerifyChecksum

	// Parse internal CIDRs - must succeed since config.Validate checks these
	for _, cidr := range cfg.Internal {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: internal CIDR %q failed to parse after validation: %v", cidr, err))
		}
		s.internalCIDRs = append(s.internalCIDRs, ipNet)
	}

	// Parse SSRF IP allowlist CIDRs - must succeed since config.Validate checks these
	for _, cidr := range cfg.SSRF.IPAllowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: SSRF IP allowlist CIDR %q failed to parse after validation: %v", cidr, err))
		}
		s.ipAllowlistCIDRs = append(s.ipAllowlistCIDRs, ipNet)
	}

	s.trustedDomains = cfg.TrustedDomains
	s.rawAPIAllowlist = cfg.APIAllowlist

	// Install the DNS resolver. When dns.host_overrides is empty the wrapper
	// degrades to a plain delegation to net.DefaultResolver - this keeps a
	// single code path through the rest of the scanner and proxy regardless
	// of whether overrides are configured.
	s.resolver = NewStaticOverrideResolver(cfg.DNS.HostOverrides, nil)

	// Initialize data budget if configured
	if cfg.FetchProxy.Monitoring.MaxDataPerMinute > 0 {
		s.dataBudget = NewDataBudget(cfg.FetchProxy.Monitoring.MaxDataPerMinute)
	}

	// Set minimum env secret length from config (default 16)
	s.minEnvSecretLen = cfg.DLP.MinEnvSecretLength
	if s.minEnvSecretLen <= 0 {
		s.minEnvSecretLen = 16
	}

	// Extract high-entropy environment variables for leak detection
	if cfg.DLP.ScanEnv {
		s.envSecrets = extractEnvSecrets(s.minEnvSecretLen)
	}

	// Load explicit secrets from secrets file
	if cfg.DLP.SecretsFile != "" {
		fileSecrets, err := LoadSecretsFile(cfg.DLP.SecretsFile, s.minEnvSecretLen)
		if err != nil {
			panic(fmt.Sprintf("BUG: secrets file %q failed after validation: %v",
				cfg.DLP.SecretsFile, err))
		}
		s.fileSecrets = dedupSecrets(fileSecrets, s.envSecrets)
		if len(s.fileSecrets) == 0 {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file %q yielded zero usable secrets\n",
				cfg.DLP.SecretsFile)
		}
	}

	// Compile response scanning patterns - must succeed since config.Validate checks these
	if cfg.ResponseScanning.Enabled {
		s.responseEnabled = true
		s.responseAction = cfg.ResponseScanning.Action
		for _, p := range cfg.ResponseScanning.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				panic(fmt.Sprintf("BUG: response pattern %q failed after validation: %v", p.Name, err))
			}
			requiredLiteralsAny := responsePatternRequiredLiterals(p.Regex)
			s.responsePatterns = append(s.responsePatterns, &compiledPattern{
				name:                p.Name,
				re:                  re,
				bundle:              p.Bundle,
				bundleVersion:       p.BundleVersion,
				requiredLiteralsAny: requiredLiteralsAny,
			})

			// Compile optional-whitespace variant: \s+ → \s* so that
			// "ignoreallpreviousinstructions" (ZW-stripped with no spaces)
			// still matches injection patterns. Handles the combined attack
			// where ZW chars split keywords AND replace word separators.
			optRegex := strings.ReplaceAll(p.Regex, `\s+`, `\s*`)
			optRegex = strings.ReplaceAll(optRegex, `[-,;:.\s]+`, `[-,;:.\s]*`)
			if optRegex != p.Regex {
				optRe, optErr := regexp.Compile(optRegex)
				if optErr == nil {
					s.responseOptSpacePatterns = append(s.responseOptSpacePatterns, &compiledPattern{
						name:                p.Name,
						re:                  optRe,
						bundle:              p.Bundle,
						bundleVersion:       p.BundleVersion,
						requiredLiteralsAny: requiredLiteralsAny,
					})
				}
			}

			// Compile vowel-folded variant: fold all vowels (e,i,o,u -> a) in the
			// regex so that confusable-vowel attacks are caught. An attacker using
			// o-stroke (maps to o) to replace both 'o' and 'u' produces "instroctions"
			// after confusable mapping. Standard patterns fail. Vowel-folding both
			// the pattern and the content makes them match.
			// Extract any leading (?flags) group before folding. FoldVowels would
			// corrupt flag chars (e.g. i->a turning (?im) into (?am), which is invalid).
			vfRegex := p.Regex
			vfPrefix := ""
			if strings.HasPrefix(vfRegex, "(?") {
				if end := strings.Index(vfRegex, ")"); end > 1 {
					flags := vfRegex[2:end]
					allFlags := true
					for _, r := range flags {
						if !strings.ContainsRune("imsU-", r) {
							allFlags = false
							break
						}
					}
					if allFlags {
						vfPrefix = vfRegex[:end+1]
						vfRegex = vfRegex[end+1:]
					}
				}
			}
			vfRegex = vfPrefix + normalize.FoldVowels(vfRegex)
			if vfRegex != p.Regex {
				vfRe, vfErr := regexp.Compile(vfRegex)
				if vfErr == nil {
					s.responseVowelFoldPatterns = append(s.responseVowelFoldPatterns, &compiledPattern{
						name:                p.Name,
						re:                  vfRe,
						bundle:              p.Bundle,
						bundleVersion:       p.BundleVersion,
						requiredLiteralsAny: requiredLiteralsAny,
					})
				}
			}
		}
	}

	// Build response pre-filters for keyword-gated regex skipping.
	// Each pattern set gets its own pre-filter because opt-space and
	// vowel-fold transforms change which keywords appear in content.
	if len(s.responsePatterns) > 0 {
		s.responsePreFilter = newResponsePreFilter(s.responsePatterns)
	}
	if len(s.responseOptSpacePatterns) > 0 {
		s.responseOptSpacePreFilter = newResponsePreFilter(s.responseOptSpacePatterns)
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		s.responseVowelFoldPreFilter = newResponsePreFilter(s.responseVowelFoldPatterns)
	}

	// Build address protection checker if enabled.
	if cfg.AddressProtection.Enabled {
		agentAddrs := make(map[string][]string)
		for name, agent := range cfg.Agents {
			if name != "_default" && !cfg.LicenseAgentsFeature {
				continue
			}
			if len(agent.AllowedAddresses) > 0 {
				agentAddrs[name] = agent.AllowedAddresses
			}
		}
		s.addressChecker = addressprotect.NewChecker(&cfg.AddressProtection, agentAddrs)
	}

	return s
}

// AddressChecker returns the address protection checker, or nil if disabled.
func (s *Scanner) AddressChecker() *addressprotect.Checker {
	return s.addressChecker
}

// IsInternalIP checks whether the given IP falls within any configured
// internal CIDR. Returns false when SSRF protection is disabled (no CIDRs).
func (s *Scanner) IsInternalIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) to
	// their 4-byte IPv4 form so they match IPv4 CIDRs like 127.0.0.0/8.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, cidr := range s.internalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrustedDomain checks if a hostname matches any trusted domain pattern.
// Trusted domains allow connections to internal IPs with advisory logging
// instead of blocking. IP literals are always rejected - trusted domains
// only match hostnames to prevent SSRF bypass via raw IP addresses.
func (s *Scanner) IsTrustedDomain(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	// Reject IP literals: trusted domains match hostnames only.
	// Without this, an attacker could add a raw IP to trusted_domains
	// and bypass SSRF protection entirely.
	if net.ParseIP(hostname) != nil {
		return false
	}
	for _, pattern := range s.trustedDomains {
		if MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}

// HostResolver returns the resolver used for SSRF DNS lookups and the proxy
// dial path. It honors dns.host_overrides if configured and falls back to
// net.DefaultResolver otherwise. Always non-nil for a Scanner built via New().
func (s *Scanner) HostResolver() Resolver {
	return s.resolver
}

// IsIPAllowlisted checks if an IP is in the SSRF IP allowlist (ssrf.ip_allowlist).
// Used by checkSSRF and the dial-level SSRF check to exempt specific IP ranges.
func (s *Scanner) IsIPAllowlisted(ip net.IP) bool {
	for _, cidr := range s.ipAllowlistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsInAPIAllowlist checks if a hostname matches any entry in api_allowlist.
// Unlike the scanner's allowlist field (which is mode-gated to strict), this
// checks the raw config allowlist regardless of mode - used for SSRF hint
// generation and config-mismatch classification.
func (s *Scanner) IsInAPIAllowlist(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, pattern := range s.rawAPIAllowlist {
		if MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}

// Close marks the scanner unusable for new BeginUse callers and tears
// down internal resources once every active BeginUse has invoked release.
// Idempotent; further calls are no-ops.
//
// Drain semantics: the call site (typically Proxy.Reload's `go old.Close()`)
// gets scannerCloseDrainTimeout to wait for in-flight users. If drain
// completes inside that window, teardown runs synchronously and Close
// returns once Drained is true. If the timeout fires (a hung scan, an
// adversarial slow-loris client), Close hands teardown off to a detached
// goroutine that waits indefinitely for inUse to reach zero before
// releasing the rateLimiter lifecycle and stopping the dataBudget ticker. The forced-teardown
// path is gone: a hung user can no longer end up calling Scan on a
// scanner whose background resources have been torn down underneath it.
//
// Trade-off: a permanently-hung scan retains the prior scanner forever.
// That is preferable to fail-open enforcement; the proxy's reload-mu
// guard plus the maxBaselineTools cap bound exposure, and the new
// scanner already serves all post-swap traffic so the orphan affects
// only the single hung request.
func (s *Scanner) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	s.closeMu.Unlock()

	drainDone := make(chan struct{})
	go func() {
		s.inUse.Wait()
		close(drainDone)
	}()
	select {
	case <-drainDone:
		s.tearDown()
	case <-time.After(scannerCloseDrainTimeout):
		// Drain timed out. Do NOT tear down background resources mid-scan;
		// hand off to a detached goroutine that waits indefinitely for
		// the hung user to release. Drained() flips only once that
		// goroutine actually completes teardown.
		go func() {
			s.inUse.Wait()
			s.tearDown()
		}()
	}
}

// tearDown releases scanner lifecycle state and flips drained=true. Safe to
// call exactly once per Close transition.
func (s *Scanner) tearDown() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	if s.dataBudget != nil {
		s.dataBudget.Close()
	}
	s.drained.Store(true)
}

// BeginUse registers an in-flight scanner user. Callers MUST invoke the
// returned release func when finished (defer is the canonical idiom).
// Returns ok=false if Close has already been initiated; callers in that
// case must re-Load the proxy's scanner pointer to acquire the freshly
// swapped-in instance and retry. Cheap: two atomics + a WaitGroup Add on
// the happy path.
func (s *Scanner) BeginUse() (release func(), ok bool) {
	s.closeMu.RLock()
	if s.closed {
		s.closeMu.RUnlock()
		return nil, false
	}
	s.inUse.Add(1)
	s.closeMu.RUnlock()
	return s.inUse.Done, true
}

// Closed reports whether Close has been initiated. Used by tests to assert
// hot-reload drained the prior scanner. Production callers should rely on
// BeginUse's ok return instead.
func (s *Scanner) Closed() bool {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	return s.closed
}

// Drained reports whether Close has finished its teardown - drain wait
// returned (or timed out), and the rateLimiter / dataBudget cleanup
// goroutines have been signaled to stop. Distinct from Closed, which
// flips at the start of Close before drain runs. Tests use Drained to
// assert the close goroutine actually completed; production code has no
// reason to read this.
func (s *Scanner) Drained() bool {
	return s.drained.Load()
}

// RecordRequest records response data for per-domain data budget tracking.
// Call this AFTER Scan() returns Allowed=true and the response is fetched.
// Rate limiting is handled atomically inside Scan() via CheckAndRecord.
// dataBytes is the response size; pass 0 if unknown or not yet fetched.
// Uses baseDomain normalization to match checkDataBudget's tracking.
func (s *Scanner) RecordRequest(hostname string, dataBytes int) {
	if s.dataBudget != nil && dataBytes > 0 {
		s.dataBudget.Record(baseDomain(hostname), dataBytes)
	}
}

// HintForScanner returns the terse, agent-facing block reason for a scanner
// label (the AgentReason from the central remediation table). It deliberately
// carries NO config knob or containment-mechanism name: this value reaches the
// blocked agent via the X-Pipelock-Hint response header and the block response
// body, so naming the remediation knob here would teach the agent to unblock
// itself (confused deputy). Operators get the exact allow-path from
// `pipelock explain` and the audit remediation_hint, not the agent response.
// Returns "" for an unknown label (fail-safe).
func HintForScanner(label string) string {
	g, _ := GuidanceFor(label)
	return g.AgentReason
}

// HintForBlock returns the terse, agent-facing block reason for a blocked scan
// result, using the scan Reason to disambiguate same-label variants. Returns ""
// for an allowed or nil result, or an unknown label (fail-safe).
func HintForBlock(r *Result) string {
	if r == nil || r.Allowed {
		return ""
	}
	g, _ := GuidanceForResult(r.Scanner, r.Reason)
	return g.AgentReason
}

// Scan checks a URL against all scanners and returns the result.
// Blocked results include a Hint field with actionable guidance.
// Fail-closed: nil or already-cancelled contexts are rejected before scanning.
//
// Heartbeat fires on EVERY return (including the early fail-closed path
// for nil/cancelled contexts) via defer. The watchdog interprets the
// heartbeat as "Scan is making progress, not wedged in a regex"; a fast
// reject is still progress and must register so a flood of cancelled-
// context probes does not falsely trip the wedge detector.
func (s *Scanner) Scan(ctx context.Context, rawURL string) Result {
	defer func() {
		if h := s.heartbeat.Load(); h != nil {
			h.fn()
		}
	}()
	if ctx == nil || ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context unavailable",
			Scanner: ScannerContext,
			Score:   1.0,
			Hint:    HintForScanner(ScannerContext),
		}
	}
	r := s.scan(ctx, rawURL)
	if !r.Allowed && r.Hint == "" {
		r.Hint = HintForBlock(&r)
	}
	return r
}

// scan checks a URL against all scanners and returns the result.
// DLP runs on the hostname BEFORE DNS resolution to prevent secret exfiltration
// via DNS queries (e.g., "sk-ant-xxx.evil.com" leaks the key during resolution).
func (s *Scanner) scan(ctx context.Context, rawURL string) (result Result) {
	if s.maxURLLength > 0 && len(rawURL) > s.maxURLLength {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("URL length %d exceeds maximum %d", len(rawURL), s.maxURLLength),
			Scanner: ScannerLength,
			Score:   0.8,
		}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Result{Allowed: false, Reason: "invalid URL", Scanner: ScannerParser, Score: 1.0}
	}

	// Normalize hostname for consistent matching
	hostname := strings.ToLower(parsed.Hostname())

	// Canonicalize non-standard IP notations (hex, octal, decimal integer)
	// so that allowlist/blocklist/DLP checks all see the same dotted-decimal
	// form. Without this, 0x7f000001 bypasses a blocklist entry for 127.0.0.1.
	// Also update parsed.Host so downstream consumers (checkDLP, checkEntropy,
	// exempt_domains matching) all see the canonical form.
	if altIP := parseAlternativeIP(hostname); altIP != nil {
		hostname = altIP.String()
		port := parsed.Port()
		if port != "" {
			parsed.Host = hostname + ":" + port
		} else {
			parsed.Host = hostname
		}
	}

	// Scheme check -
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("scheme %q not allowed: only http and https", parsed.Scheme),
			Scanner: ScannerScheme,
			Score:   1.0,
		}
	}

	// CRLF injection check - %0D%0A in URLs enables header injection.
	// Runs early because CRLF is never legitimate in a URL.
	if result := checkCRLF(rawURL); !result.Allowed {
		return result
	}

	// Path traversal check - /../ sequences are defense-in-depth.
	if result := checkPathTraversal(parsed); !result.Allowed {
		return result
	}

	// Allowlist check - if configured, only allowlisted domains are permitted.
	// Runs before DNS to reject disallowed domains without any network I/O.
	if result := s.checkAllowlist(hostname); !result.Allowed {
		return result
	}

	// Blocklist check - before DNS to avoid resolving known-bad domains.
	if result := s.checkBlocklist(hostname); !result.Allowed {
		return result
	}

	// Core SSRF literal - immutable safety floor for IP literals. Runs ALWAYS,
	// even when cfg.Internal is nil (SSRF disabled). Blocks direct requests
	// to private IPs (127.0.0.1, 169.254.169.254, 10.x, etc.). Respects
	// ssrf.ip_allowlist for operator overrides.
	if result := s.checkCoreSSRFLiteral(hostname); !result.Allowed {
		return result
	}

	// SigV4 presigned URL carve-out. Detect once before content-scanning
	// stages so core DLP, main DLP, and query-entropy all see the same
	// scrubbed URL. The scrub replaces ONLY the AKIA component of a
	// structurally validated X-Amz-Credential value with a same-length
	// lowercase placeholder; the AKIA appearing in any other URL component
	// (path, hostname, other query params) is left untouched and still
	// triggers core/main DLP blocks. Query entropy on the credential value
	// drops below threshold once the AKIA is normalised, so legitimate
	// presigned URLs stop tripping on the issuer's deliberately diverse
	// scope string. See sigv4.go.
	sigV4 := detectValidSigV4(parsed)
	scanURL := parsed
	if sigV4.Valid {
		scanURL = scrubSigV4Credential(parsed, sigV4.KeyID)
	}

	// Core DLP - immutable safety floor. Runs BEFORE main DLP, BEFORE DNS.
	// Core findings are FINAL; the main scanner cannot override a core block.
	if result := s.checkCoreDLP(scanURL); !result.Allowed {
		return result
	}

	// DLP + entropy on hostname BEFORE DNS resolution.
	// Prevents secret exfiltration via DNS queries for domains like
	// "sk-ant-xxxx.evil.com" where the subdomain encodes a secret.
	dlpResult, dlpWarns := s.checkDLP(scanURL)
	dlpWarns = deduplicateWarnMatches(dlpWarns)
	if !dlpResult.Allowed {
		dlpResult.WarnMatches = dlpWarns
		s.emitDLPWarns(ctx, dlpWarns)
		return dlpResult
	}
	// Attach DLP warn matches to whatever result is returned from here on.
	// The defer fires on every return path, including blocks by later scanners.
	// When SigV4 detection validated the URL, also mark the allow result as
	// adaptive-neutral and attach a long-expiry warn for audit visibility.
	defer func() {
		if sigV4.Valid && result.Allowed && result.Class == ClassThreat {
			result.Class = ClassStructuralExemption
		}
		if sigV4.Valid && result.Allowed && sigV4.Expires > sigV4LongExpiryThreshold {
			dlpWarns = append(dlpWarns, WarnMatch{
				PatternName: WarnPatternSigV4LongExpiry,
				Severity:    "info",
			})
		}
		result.WarnMatches = dlpWarns
		s.emitDLPWarns(ctx, dlpWarns)
	}()
	if result := s.checkEntropy(scanURL); !result.Allowed {
		return result
	}

	// Subdomain entropy check - catches base64/hex encoded data in subdomains
	// (e.g., "aGVsbG8.evil.com" exfiltrating data via DNS queries).
	if result := s.checkSubdomainEntropy(hostname); !result.Allowed {
		return result
	}

	// SSRF protection - DNS resolution happens here, safe after DLP.
	// When active, core CIDRs are always included via mergedSSRFCIDRs()
	// so private ranges (10.x, 172.16.x, 192.168.x, loopback, link-local)
	// cannot be removed from the check set via config alone.
	if result := s.checkSSRF(ctx, hostname); !result.Allowed {
		return result
	}

	// Rate limit check (per-domain)
	if result := s.checkRateLimit(hostname); !result.Allowed {
		return result
	}

	// Data budget check (per-domain sliding window)
	if result := s.checkDataBudget(hostname); !result.Allowed {
		return result
	}

	// Final context check: catch cancellations that arrived during in-memory
	// scanning (blocklist, DLP, entropy) before returning an allow verdict.
	if ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context cancelled",
			Scanner: ScannerContext,
			Score:   1.0,
		}
	}

	return Result{Allowed: true, Scanner: ScannerAll, Score: 0.0}
}

// parseAlternativeIP decodes non-standard IP address notations that
// net.ParseIP does not handle: hex (0x7f000001), octal (0177.0.0.1),
// decimal integer (2130706433), and mixed-radix dotted notation.
// Attackers use these to bypass SSRF checks that only recognize
// standard dotted-decimal. Returns nil if the hostname is not an
// alternative IP notation.
func parseAlternativeIP(hostname string) net.IP {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil
	}

	// Dotted notation with possible hex/octal octets (e.g., 0177.0.0.1, 0x7f.0.0.1).
	if strings.Contains(hostname, ".") {
		parts := strings.Split(hostname, ".")
		if len(parts) != 4 {
			return nil
		}
		octets := make([]byte, 4)
		for i, part := range parts {
			val, err := strconv.ParseUint(part, 0, 16) // base 0: auto-detect hex/octal/decimal; 16 bits max per octet
			if err != nil || val > 255 {
				return nil
			}
			octets[i] = byte(val)
		}
		// Only return if at least one octet used non-standard notation.
		// Standard dotted-decimal is already handled by net.ParseIP.
		hasNonStandard := false
		for _, part := range parts {
			if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") ||
				(len(part) > 1 && part[0] == '0' && part != "0") {
				hasNonStandard = true
				break
			}
		}
		if !hasNonStandard {
			return nil
		}
		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	}

	// Single integer notation: hex (0x7f000001), octal (017700000001),
	// or decimal (2130706433). Represents the full 32-bit IPv4 address.
	val, err := strconv.ParseUint(hostname, 0, 32) // base 0: auto-detect; 32 bits for full IPv4
	if err != nil {
		return nil
	}
	return net.IPv4(byte(val>>24), byte(val>>16&0xFF), byte(val>>8&0xFF), byte(val&0xFF))
}

// metadataIPv4s lists the well-known cloud-provider instance-metadata IPv4
// endpoints that are operationally distinct from generic private-network
// blocks. AWS / Azure / GCP IMDS all share 169.254.169.254. Azure also exposes
// the WireServer at 168.63.129.16. Hits on these addresses are reported with
// ScannerSSRFMetadata so the block-reason header carries the dedicated
// `ssrf_metadata` code (vs. the generic `ssrf_private_ip`).
var metadataIPv4s = map[string]struct{}{
	"169.254.169.254": {}, // AWS / Azure / GCP IMDS
	"168.63.129.16":   {}, // Azure WireServer
}

// metadataIPv6 lists the canonical IPv6 instance-metadata endpoints.
var metadataIPv6 = map[string]struct{}{
	"fd00:ec2::254": {}, // AWS IMDSv6
}

// IsCloudMetadataIP returns true when the resolved IP belongs to a recognised
// cloud-provider metadata service. The caller uses this to upgrade a generic
// SSRF block into the more specific metadata classification, matching the
// dedicated blockreason.SSRFMetadata code.
func IsCloudMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		_, ok := metadataIPv4s[v4.String()]
		return ok
	}
	_, ok := metadataIPv6[ip.String()]
	return ok
}

func isCloudMetadataIP(ip net.IP) bool {
	return IsCloudMetadataIP(ip)
}

// checkSSRF blocks requests to internal/private IP ranges.
// When no internal CIDRs are configured (nil slice), SSRF protection is disabled.
// To block loopback, link-local, etc., include those CIDRs in config.Internal.
// When SSRF IS active, core CIDRs are always included in the check set.
func (s *Scanner) checkSSRF(ctx context.Context, hostname string) Result {
	// Check context before the SSRF-disabled fast path so cancelled requests
	// don't slip through when internalCIDRs is empty.
	if ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context cancelled",
			Scanner: ScannerContext,
			Score:   1.0,
		}
	}
	if len(s.internalCIDRs) == 0 {
		return Result{Allowed: true}
	}

	// When SSRF is active, merge core CIDRs so private ranges can never
	// be removed from the check set via config alone.
	allCIDRs := s.mergedSSRFCIDRs()

	// Decode non-standard IP notations (hex, octal, decimal integer) BEFORE
	// DNS resolution. Attackers use 0x7f000001, 0177.0.0.1, or 2130706433
	// to reach 127.0.0.1 without net.ParseIP recognizing it. If the hostname
	// decodes to a valid IP, check CIDRs directly and skip DNS.
	if altIP := parseAlternativeIP(hostname); altIP != nil {
		if v4 := altIP.To4(); v4 != nil {
			altIP = v4
		}
		for _, cidr := range allCIDRs {
			if cidr.Contains(altIP) {
				scannerLabel := ScannerSSRF
				blockReason := fmt.Sprintf("SSRF blocked: %s decodes to internal IP %s", hostname, altIP)
				if isCloudMetadataIP(altIP) {
					scannerLabel = ScannerSSRFMetadata
					blockReason = fmt.Sprintf("SSRF blocked: %s decodes to cloud metadata endpoint %s", hostname, altIP)
				}
				return Result{
					Allowed: false,
					Reason:  blockReason,
					Scanner: scannerLabel,
					Score:   1.0,
				}
			}
		}
		// Non-standard IP that doesn't match internal CIDRs - allow.
		return Result{Allowed: true}
	}

	// Resolve hostname to IP for SSRF check.
	// Fail closed: if we can't resolve DNS, we can't verify the IP is safe.
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 5*time.Second) // 5s: DNS resolution ceiling; inherits caller cancellation
	defer dnsCancel()
	ips, err := s.resolver.LookupHost(dnsCtx, hostname)
	if err != nil {
		// Caller cancellation or deadline must route through the normal
		// fail-closed ScannerContext path. dnsCtx inherits ctx, so a
		// client abort or request deadline surfaces here as
		// context.Canceled / DeadlineExceeded. Classifying those as
		// infrastructure errors would make cancelled SSRF probes
		// adaptive-neutral, contradicting the CLAUDE.md rule that
		// context cancellation always defaults to block.
		if ctx.Err() != nil {
			return Result{
				Allowed: false,
				Reason:  "request context cancelled",
				Scanner: ScannerContext,
				Score:   1.0,
				Hint:    HintForScanner(ScannerContext),
			}
		}
		// Genuine resolver failure. Classify as infrastructure error,
		// not a threat. Fail-closed is preserved (Allowed=false, request
		// still blocked), but adaptive enforcement must not treat
		// resolver wobble as evidence of an adversary. Without this
		// classification, a burst of DNS timeouts accumulates
		// SignalBlock points until the session is pushed into airlock
		// lockdown.
		//
		// Split the resolver failure mode into a DNSErrorKind so the
		// audit emit path can drop the misleading mitre_technique=T1046
		// tag (and the "SSRF check failed" reason text) on
		// non-adversarial DNS errors. The label fix is presentational;
		// Scanner stays ScannerSSRF so existing suppression rules, layer
		// header values, and metrics keyed on the canonical label keep
		// working for operators that already consume them.
		kind, reason := classifyDNSError(hostname, err)
		return Result{
			Allowed:      false,
			Reason:       reason,
			Scanner:      ScannerSSRF,
			Score:        1.0,
			Class:        ClassInfrastructureError,
			DNSErrorKind: kind,
		}
	}

	// Trusted domains bypass the internal-IP CIDR check. All other scanners
	// (DLP, blocklist, entropy) still apply - only the RFC1918 resolution
	// check is skipped. This lets operators allowlist internal services
	// (e.g., local inference servers) without disabling SSRF protection globally.
	if s.IsTrustedDomain(hostname) {
		return Result{Allowed: true}
	}

	for _, ipStr := range ips {
		// Strip IPv6 zone ID (e.g. "::1%eth0" → "::1"). Zone IDs cause
		// net.ParseIP to return nil, silently skipping the CIDR check.
		if idx := strings.Index(ipStr, "%"); idx != -1 {
			ipStr = ipStr[:idx]
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}

		// Check against internal CIDRs (core + config)
		for _, cidr := range allCIDRs {
			if cidr.Contains(ip) {
				// IP allowlist exemption: operator explicitly trusts this range.
				if s.IsIPAllowlisted(ip) {
					continue
				}
				scannerLabel := ScannerSSRF
				blockReason := fmt.Sprintf("SSRF blocked: %s resolves to internal IP %s", hostname, ipStr)
				if isCloudMetadataIP(ip) {
					scannerLabel = ScannerSSRFMetadata
					blockReason = fmt.Sprintf("SSRF blocked: %s resolves to cloud metadata endpoint %s", hostname, ipStr)
				}
				r := Result{
					Allowed: false,
					Reason:  blockReason,
					Scanner: scannerLabel,
					Score:   1.0,
				}
				// If the domain is in api_allowlist, this is a config
				// mismatch (not a real attack): classify it so adaptive
				// enforcement doesn't escalate. The agent-facing hint stays
				// terse (no knob); the operator gets the exact allow-path
				// (ssrf.ip_allowlist for an IP literal, trusted_domains for a
				// hostname) from `pipelock explain` and the audit hint.
				if s.IsInAPIAllowlist(hostname) {
					r.Hint = HintForScanner(scannerLabel)
					r.Class = ClassConfigMismatch
				}
				return r
			}
		}

	}

	return Result{Allowed: true}
}

// checkAllowlist rejects requests to domains not in the allowlist.
// When the allowlist is empty, all domains are permitted (allowlist is opt-in).
// Uses MatchDomain for consistent wildcard matching with the blocklist.
func (s *Scanner) checkAllowlist(hostname string) Result {
	if len(s.allowlist) == 0 {
		return Result{Allowed: true}
	}
	for _, pattern := range s.allowlist {
		if MatchDomain(hostname, pattern) {
			return Result{Allowed: true}
		}
	}
	return Result{
		Allowed: false,
		Reason:  fmt.Sprintf("domain not in allowlist: %s", hostname),
		Scanner: ScannerAllowlist,
		Score:   1.0,
	}
}

// checkBlocklist checks the hostname against the domain blocklist.
func (s *Scanner) checkBlocklist(hostname string) Result {
	for _, pattern := range s.blocklist {
		if MatchDomain(hostname, pattern) {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("domain blocked: %s matches %s", hostname, pattern),
				Scanner: ScannerBlocklist,
				Score:   1.0,
			}
		}
	}
	return Result{Allowed: true}
}

// checkCRLF detects CRLF injection sequences in URLs. CR+LF bytes in a URL
// enable HTTP header injection at the target server. Go's http library rejects
// raw \r\n in requests, but we detect encoded variants (%0d%0a, double-encoded)
// for defense-in-depth visibility.
//
// Fragments are excluded: they are never sent to the upstream server, so CRLF
// in a fragment cannot inject headers.
func checkCRLF(rawURL string) Result {
	// Strip fragment - it never reaches the server.
	if idx := strings.IndexByte(rawURL, '#'); idx != -1 {
		rawURL = rawURL[:idx]
	}
	lower := strings.ToLower(rawURL)

	// Check for encoded CRLF pair: %0d%0a (the primary attack vector).
	if strings.Contains(lower, "%0d%0a") {
		return Result{
			Allowed: false,
			Reason:  "CRLF injection sequence in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for double-encoded CRLF pair: %250d%250a.
	if strings.Contains(lower, "%250d%250a") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded CRLF injection sequence in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for bare encoded LF or CR. Some servers (e.g., Node.js HTTP
	// parsers) accept a bare LF as a header terminator, so %0a alone is
	// enough to inject headers without a preceding %0d.
	if strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d") {
		return Result{
			Allowed: false,
			Reason:  "encoded CR or LF in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for double-encoded bare LF or CR: %250a, %250d.
	if strings.Contains(lower, "%250a") || strings.Contains(lower, "%250d") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded CR or LF in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for raw CR or LF bytes (should not appear in URLs).
	if strings.ContainsAny(rawURL, "\r\n") {
		return Result{
			Allowed: false,
			Reason:  "raw CRLF bytes in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	return Result{Allowed: true}
}

// checkPathTraversal detects directory traversal sequences in URL paths.
// Target servers are responsible for path safety, but detecting traversal
// provides defense-in-depth and visibility into potential attacks.
func checkPathTraversal(parsed *url.URL) Result {
	// Check the raw path to catch encoded variants. url.Parse decodes %2e
	// to '.' in Path but preserves encoding in RawPath (when it differs).
	rawPath := parsed.RawPath
	if rawPath == "" {
		rawPath = parsed.Path
	}
	lowerPath := strings.ToLower(rawPath)

	// Detect ".." as a path segment in raw and encoded forms.
	// Match segment-bounded traversal: /<dotdot><sep> or trailing /<dotdot>,
	// where sep is / \ %2f %5c and dots may be encoded as %2e.
	dotdots := []string{"..", "%2e.", ".%2e", "%2e%2e"}
	seps := []string{"/", "\\", "%2f", "%5c"}

	for _, dd := range dotdots {
		for _, left := range seps {
			for _, right := range seps {
				// <left><dd><right>  e.g. /../, %2f..%5c, \..%2f
				if strings.Contains(lowerPath, left+dd+right) {
					return Result{Allowed: false, Reason: "path traversal sequence in URL", Scanner: ScannerPathTraversal, Score: 0.7}
				}
			}
			// <left><dd> at end of path - no trailing separator
			if strings.HasSuffix(lowerPath, left+dd) {
				return Result{Allowed: false, Reason: "path traversal sequence in URL", Scanner: ScannerPathTraversal, Score: 0.7}
			}
		}
	}

	// Double-encoded variants: %252e%252e bounded by separators.
	if strings.Contains(lowerPath, "/%252e%252e/") ||
		strings.Contains(lowerPath, "/%252e%252e%252f") ||
		strings.HasSuffix(lowerPath, "/%252e%252e") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded path traversal in URL",
			Scanner: ScannerPathTraversal,
			Score:   0.7,
		}
	}

	return Result{Allowed: true}
}

// checkRateLimit enforces per-domain rate limiting using a sliding window.
// Uses atomic CheckAndRecord to prevent TOCTOU races where concurrent
// requests could both pass the check before either records.
// Uses baseDomain normalization to prevent subdomain rotation bypass
// (e.g., a.evil.com, b.evil.com each getting separate rate limit windows).
func (s *Scanner) checkRateLimit(hostname string) Result {
	if s.rateLimiter == nil {
		return Result{Allowed: true}
	}

	if !s.rateLimiter.CheckAndRecord(baseDomain(hostname)) {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("rate limit exceeded for %s", hostname),
			Scanner: ScannerRateLimit,
			Score:   0.7,
			Class:   ClassProtective,
		}
	}

	return Result{Allowed: true}
}

// maxDecodeRounds is a safety ceiling for iterative URL decoding.
// The loop exits early when decoding produces no change (decoded == s),
// so this limit only matters for pathological inputs. URL decoding is
// microsecond-cheap per round, so a generous ceiling has no real cost.
const maxDecodeRounds = 500

// IterativeDecode applies URL decoding until the string stops changing
// or the safety ceiling is reached. Catches multi-layer encoding (e.g., %252D → %2D → -).
// Exported for use by the fetch proxy to normalize display URLs.
func IterativeDecode(s string) string {
	for range maxDecodeRounds {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return s
}

// stripURLNoise removes URL separator characters that break DLP regex matching
// when secrets are fragmented across path/query boundaries. Strips characters that
// are valid in URLs but not in API key character classes [a-zA-Z0-9\-_]. Attackers
// insert dots, slashes, spaces, and other noise to split key patterns.
func stripURLNoise(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', ' ', '\t', '\n', '\r', '+', ',', ';', '|':
			return -1
		}
		return r
	}, s)
}

// orderedQueryConcat concatenates all query parameter values in their original URL
// order and returns the result. Catches secrets split across multiple query params
// (e.g., "?part1=sk-ant-api03-&part2=AAAA..." → "sk-ant-api03-AAAA...").
// Uses RawQuery instead of url.Values to preserve parameter order.
func orderedQueryConcat(rawQuery string) string {
	var b strings.Builder
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			b.WriteString(IterativeDecode(value))
		}
	}
	return b.String()
}

// decodedResult pairs decoded text with the encoding that produced it.
type decodedResult struct {
	text     string
	encoding string
}

// Encoding labels for decoded results.
const (
	encodingHex    = "hex"
	encodingBase64 = "base64"
	encodingBase32 = "base32"
	encodingURL    = "url"
	encodingHTML   = "html_entity"
)

const (
	maxDecodeCandidates = 4096
	// maxDecodeTotalBytes bounds the SUM of decoded-candidate bytes processed in
	// one fixpoint walk. It is the real work ceiling (decode + DLP match cost),
	// and it replaces a per-candidate ceiling: a low per-candidate cap is itself
	// a bypass, because an attacker can pad a stacked-encoded secret past it. The
	// budget sits above the 5MB request-body scan limit so a secret encoded
	// inside a large body is still fully decoded, while a bushy decode tree
	// cannot amplify into unbounded CPU/memory. Standard decodes (base64, hex,
	// base32, URL) only shrink their input, so no single candidate exceeds the
	// entry size, which is itself bounded by this budget.
	maxDecodeTotalBytes = 8 * 1024 * 1024
)

// hexPrefixReplacer strips two-char hex prefix notations (\x, \X, 0x, 0X).
// Package-level to avoid repeated construction on every normalizeHex call.
var hexPrefixReplacer = strings.NewReplacer(`\x`, "", `\X`, "", "0x", "", "0X", "")

// normalizeHex strips common hex-notation delimiters so that delimiter-separated
// hex strings can be decoded by hex.DecodeString. Handles:
//   - \x / \X prefix notation: \x73\x6b → 736b
//   - 0x / 0X prefix notation: 0x73 0x6b → 736b
//   - Colon-separated:         73:6b     → 736b
//   - Space-separated:         73 6b     → 736b
//   - Hyphen-separated:        73-6b     → 736b
//   - Comma-separated:         73,6b     → 736b
//
// Returns "" if the result is not valid hex (odd length or non-hex chars).
func normalizeHex(s string) string {
	if len(s) < 4 {
		return ""
	}

	// Strip two-char prefix sequences first (\x, 0x).
	// Must happen before single-char delimiter stripping to avoid
	// leaving stray 'x' characters from partially-matched patterns.
	out := hexPrefixReplacer.Replace(s)

	// Strip single-char delimiters.
	out = strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '-', ',':
			return -1
		default:
			return r
		}
	}, out)

	// Validate: must be even-length, non-empty, and pure hex.
	if len(out) == 0 || len(out)%2 != 0 {
		return ""
	}
	for _, c := range out {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return ""
		}
	}
	return out
}

type encodedTokenKind int

const (
	encodedTokenBase64Std encodedTokenKind = iota
	encodedTokenBase64URL
	encodedTokenBase32
)

func isASCIIWhitespaceByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isEncodedTokenByte(c byte, kind encodedTokenKind) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return kind != encodedTokenBase32
	case c >= '0' && c <= '9':
		return kind != encodedTokenBase32 || c == '2' || c == '3' || c == '4' || c == '5' || c == '6' || c == '7'
	case c == '=':
		return true
	case c == '+' || c == '/':
		return kind == encodedTokenBase64Std
	case c == '-' || c == '_':
		return kind == encodedTokenBase64URL
	default:
		return false
	}
}

// isEncodedTokenSeparator reports whether c is a delimiter an attacker may
// interleave between encoded-token characters to evade contiguous-string
// matching. The recognized set is intentionally narrow: ASCII whitespace, '.',
// and the cross-encoding characters that are invalid for the target alphabet
// (so they cannot be data bytes). Any other byte aborts normalization rather
// than being skipped, which keeps false positives down at the cost of missing
// exotic splitters (',', ':', ';', '|'). The contiguous hex path in
// matchSecretEncodingSpan covers ',', ':', '\x', and '0x' explicitly; encoded
// (base64/base32) splitting on those separators is a known, documented gap, not
// full coverage.
func isEncodedTokenSeparator(c byte, kind encodedTokenKind) bool {
	if isASCIIWhitespaceByte(c) || c == '.' {
		return true
	}
	switch kind {
	case encodedTokenBase64Std:
		return c == '-' || c == '_'
	case encodedTokenBase64URL:
		return c == '/' || c == '+'
	case encodedTokenBase32:
		return c == '-' || c == '_' || c == '/'
	default:
		return false
	}
}

// normalizeEncodedToken strips only characters that are invalid for the target
// encoding. It preserves URL-safe base64 '-' and '_' for URL-safe decode and
// preserves standard base64 '/' for standard decode, so data bytes are not
// treated as delimiters.
func normalizeEncodedToken(s string, kind encodedTokenKind) string {
	if len(s) < 4 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEncodedTokenByte(c, kind) {
			b.WriteByte(c)
			continue
		}
		if isEncodedTokenSeparator(c, kind) {
			changed = true
			continue
		}
		return ""
	}
	if !changed {
		return ""
	}
	out := b.String()
	if len(out) < 4 {
		return ""
	}
	return out
}

// hexByteSep formats a contiguous hex string with a separator between each byte
// pair. Used by matchSecretEncodingSpan to generate delimiter-separated
// variants of known secrets for substring matching.
// Example: hexByteSep("736b2d", ":") returns "73:6b:2d".
func hexByteSep(hexStr, sep string) string {
	if len(hexStr) < 4 || len(hexStr)%2 != 0 {
		return hexStr
	}
	var b strings.Builder
	b.Grow(len(hexStr) + (len(hexStr)/2-1)*len(sep))
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// hexBytePrefix formats a contiguous hex string with a prefix before each byte pair.
// Example: hexBytePrefix("736b2d", `\x`) returns `\x73\x6b\x2d`.
func hexBytePrefix(hexStr, prefix string) string {
	if len(hexStr) < 2 || len(hexStr)%2 != 0 {
		return hexStr
	}
	var b strings.Builder
	b.Grow(len(hexStr) + (len(hexStr)/2)*len(prefix))
	for i := 0; i < len(hexStr); i += 2 {
		b.WriteString(prefix)
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// decodeEncodings tries hex, base64, and base32 decoding on a string and returns
// any successfully decoded variants with encoding labels. Used by checkDLP to
// catch encoded secrets in query parameters (e.g. ?key=736b2d616e742d... is
// hex-encoded sk-ant-...). Mirrors the encoding checks in ScanTextForDLP.
func decodeEncodings(s string) []decodedResult {
	var out []decodedResult
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingHex})
	} else if normalized := normalizeHex(s); normalized != "" {
		// Delimiter-separated hex (e.g., 73:6b:2d, \x73\x6b, 0x736b).
		if decoded, err := hex.DecodeString(normalized); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingHex})
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingBase64})
		}
	}
	if normalized := normalizeEncodedToken(s, encodedTokenBase64Std); normalized != "" {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if decoded, err := enc.DecodeString(normalized); err == nil && len(decoded) > 0 {
				out = append(out, decodedResult{string(decoded), encodingBase64})
			}
		}
	}
	if normalized := normalizeEncodedToken(s, encodedTokenBase64URL); normalized != "" {
		for _, enc := range []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(normalized); err == nil && len(decoded) > 0 {
				out = append(out, decodedResult{string(decoded), encodingBase64})
			}
		}
	}
	if decoded, err := base32.StdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingBase32})
	}
	if decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingBase32})
	}
	if normalized := normalizeEncodedToken(s, encodedTokenBase32); normalized != "" {
		if decoded, err := base32.StdEncoding.DecodeString(normalized); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingBase32})
		}
		if decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingBase32})
		}
	}
	return out
}

// decodeEncodingsRecursive returns all bounded fixpoint decoding candidates for
// a possibly stacked-encoded string.
func decodeEncodingsRecursive(s string) []decodedResult {
	return decodeEncodingsFixpoint(s, false)
}

func decodeEncodingsRecursiveWithURL(s string) []decodedResult {
	return decodeEncodingsFixpoint(s, true)
}

func decodeEncodingsFixpoint(s string, includeURL bool) []decodedResult {
	if s == "" || len(s) > maxDecodeTotalBytes {
		return nil
	}

	seen := map[string]struct{}{s: {}}
	var out []decodedResult
	queue := []string{s}
	consumed := 0
	for head := 0; head < len(queue) && len(out) < maxDecodeCandidates && consumed < maxDecodeTotalBytes; head++ {
		text := queue[head]
		for _, d := range decodeEncodingsOnce(text, includeURL) {
			if d.text == "" {
				continue
			}
			if _, ok := seen[d.text]; ok {
				continue
			}
			seen[d.text] = struct{}{}
			out = append(out, d)
			consumed += len(d.text)
			if len(out) >= maxDecodeCandidates || consumed >= maxDecodeTotalBytes {
				return out
			}
			queue = append(queue, d.text)
		}
	}
	return out
}

func decodeEncodingsOnce(s string, includeURL bool) []decodedResult {
	out := decodeEncodings(s)
	if !includeURL {
		return out
	}
	if decoded := IterativeDecode(s); decoded != s && decoded != "" {
		out = append(out, decodedResult{decoded, encodingURL})
	}
	return out
}

// checkDLP runs DLP regex patterns against the full URL string including hostname.
// Scanning the full URL catches secrets encoded in subdomains (e.g., sk-proj-xxx.evil.com)
// and secrets split across query parameters. Iterative URL decoding
// prevents multi-layer encoding bypass.
func (s *Scanner) checkDLP(parsed *url.URL) (Result, []WarnMatch) {
	// Canary check is deferred to after DLP pattern evaluation (below).
	// DLP patterns provide more specific attribution ("aws_access_key" vs
	// "Canary Token"). Canary is the safety net for synthetic tokens that
	// DLP patterns don't cover. Both are evaluated - DLP wins if it matches.

	var warnMatches []WarnMatch
	type dlpTarget struct {
		text      string
		viewLabel string
	}

	// parsed.Path is already URL-decoded by Go's url.Parse.
	// For query strings, iteratively decode to catch multi-layer encoding.
	decodedQuery := IterativeDecode(parsed.RawQuery)

	targets := []dlpTarget{
		{parsed.Path, dlpViewLabel("url_path")},
		{decodedQuery, dlpViewLabel("url_query")},
	}

	// Also check decoded query keys and values individually.
	// Noise-strip each value to catch dot-separated keys (e.g. "s.k.-.a.n.t.-..." → "sk-ant-...").
	// Try hex/base64/base32 decoding to catch encoded secrets
	// (e.g. ?key=736b2d616e742d... is hex-encoded sk-ant-...).
	for key, values := range parsed.Query() {
		decodedKey := IterativeDecode(key)
		targets = append(targets, dlpTarget{decodedKey, dlpViewLabel("url_query_key")})
		for _, d := range decodeEncodingsRecursive(decodedKey) {
			targets = append(targets, dlpTarget{d.text, dlpViewLabel(d.encoding)})
		}
		if stripped := stripURLNoise(decodedKey); stripped != decodedKey {
			targets = append(targets, dlpTarget{stripped, dlpViewLabel("url_noise_stripped")})
		}
		for _, v := range values {
			decoded := IterativeDecode(v)
			targets = append(targets, dlpTarget{decoded, dlpViewLabel("url_query_value")})
			for _, d := range decodeEncodingsRecursive(decoded) {
				targets = append(targets, dlpTarget{d.text, dlpViewLabel(d.encoding)})
			}
			if stripped := stripURLNoise(decoded); stripped != decoded {
				targets = append(targets, dlpTarget{stripped, dlpViewLabel("url_noise_stripped")})
			}
		}
	}

	// Also apply iterative decode to the escaped path for double-encoded path segments.
	rawPath := parsed.RawPath
	if rawPath == "" {
		rawPath = parsed.EscapedPath()
	}
	decodedPath := IterativeDecode(rawPath)
	if decodedPath != "" && decodedPath != parsed.Path {
		targets = append(targets, dlpTarget{decodedPath, dlpViewLabel("url_path_decoded")})
	}

	// Try hex/base64/base32 decoding on path segments to catch encoded secrets
	// in URL paths (e.g. /73732d616e742d... is hex-encoded sk-ant-...).
	// Path is already URL-decoded by Go's url.Parse, so we decode the segments directly.
	for _, segment := range strings.Split(parsed.Path, "/") {
		if len(segment) >= 10 { // minimum viable encoded secret length
			for _, d := range decodeEncodingsRecursive(segment) {
				targets = append(targets, dlpTarget{d.text, dlpViewLabel(d.encoding)})
			}
		}
	}

	// Dot-collapse the hostname to catch secrets split across DNS subdomains
	// (e.g. "sk-ant-api03-.AABBCCDD.EEFFGGHH.evil.com" → "sk-ant-api03-AABBCCDDEEFFGGHHevilcom").
	// Dots break regex character classes, so individual labels pass DLP checks.
	if hostname := parsed.Hostname(); strings.Contains(hostname, ".") {
		targets = append(targets, dlpTarget{strings.ReplaceAll(hostname, ".", ""), dlpViewLabel("subdomain")})
	}

	// Strip URL noise from path to catch secrets split by dots, slashes, and
	// other separators (e.g., "/sk-ant-api03-AAAA.AAAA/AAAA" → "sk-ant-api03-AAAAAAAAAAAA").
	// Covers both dot-split and encoded-slash attacks (%2f splitting path segments).
	if stripped := stripURLNoise(parsed.Path); stripped != parsed.Path {
		targets = append(targets, dlpTarget{stripped, dlpViewLabel("url_noise_stripped")})
	}

	// Concatenate all query values in URL order to catch secrets split across
	// query parameters (e.g. "?part1=sk-ant-api03-&part2=AAAA..." → "sk-ant-api03-AAAA...").
	// Uses RawQuery to preserve parameter order (url.Values is a map with random iteration).
	// Also noise-strip the concatenation to defeat inserted garbage params
	// (e.g., "?part1=sk-ant-&mid=%20&part2=AAAA" → "sk-ant-AAAA...").
	if parsed.RawQuery != "" && strings.Contains(parsed.RawQuery, "&") {
		concat := orderedQueryConcat(parsed.RawQuery)
		targets = append(targets, dlpTarget{concat, dlpViewLabel("query_concat")})
		for _, d := range decodeEncodingsRecursive(concat) {
			targets = append(targets, dlpTarget{d.text, dlpViewLabel(d.encoding)})
		}
		if stripped := stripURLNoise(concat); stripped != concat {
			targets = append(targets, dlpTarget{stripped, dlpViewLabel("query_concat_noise_stripped")})
		}
	}

	// Coarse full-URL fallback runs after component targets so path/query spans
	// keep their more precise view labels when both views match.
	targets = append(targets, dlpTarget{parsed.String(), dlpViewLabel("url")})

	for _, target := range targets {
		if target.text == "" {
			continue
		}
		// Full normalization before DLP pattern matching: strip control chars,
		// NFKC, cross-script confusable mapping, and combining mark removal.
		// Must match response scanning depth - otherwise attackers use homoglyphs
		// in key prefixes (e.g., sk-օnt-... with Armenian օ U+0585 for 'a').
		cleaned := normalize.ForDLP(target.text)
		for _, idx := range s.dlpPreFilter.patternsToCheck(cleaned) {
			p := s.dlpPatterns[idx]
			if start, end, ok := p.matchSpan(cleaned); ok {
				// Skip pattern if the destination domain is explicitly exempted.
				if len(p.exemptDomains) > 0 && matchesDomainList(parsed.Hostname(), p.exemptDomains) {
					continue
				}
				span := newMatchSpan(start, end, target.viewLabel, p.name, p.bundle, p.bundleVersion)
				if p.warn {
					warnMatches = append(warnMatches, WarnMatch{
						PatternName: p.name,
						Severity:    p.severity,
						span:        span,
					})
					continue
				}
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: ScannerDLP,
					Score:   1.0,
					spans:   []MatchSpan{span},
				}, warnMatches
			}
		}
	}

	// Subsequence scan: try ordered combinations of query values (size 2-4)
	// to catch secrets split across params with junk values interleaved.
	// E.g., "?a=sk-&x=junk&b=ant-&y=junk&c=api03-&z=junk&d=AAAA..." -
	// combination (0,2,4,6) reconstructs "sk-ant-api03-AAAA...".
	subResult, subWarns := s.querySubsequenceDLP(parsed.RawQuery, parsed.Hostname())
	warnMatches = append(warnMatches, subWarns...)
	if !subResult.Allowed {
		return subResult, warnMatches
	}

	// Seed phrase detection on seed-safe candidates only.
	// NOT on dot-collapsed or noise-stripped text (creates synthetic word runs).
	// Covers: query values, path, hostname labels (pre-DNS exfil), path segments.
	if s.seedEnabled {
		seedTargets := []dlpTarget{
			{parsed.Path, "url_path"},
			{decodedQuery, spanViewLabel("url_decoded", "url_query")},
		}
		// Individual query values: raw decoded + encoding variants (base64/hex/base32).
		for _, values := range parsed.Query() {
			for _, v := range values {
				decoded := IterativeDecode(v)
				seedTargets = append(seedTargets, dlpTarget{decoded, spanViewLabel("url_decoded", "url_query_value")})
				for _, d := range decodeEncodingsRecursive(decoded) {
					seedTargets = append(seedTargets, dlpTarget{d.text, spanViewLabel(d.encoding+"_decoded", "url_query_value")})
				}
			}
		}
		// Ordered query-value concatenation with spaces: catches seed phrases
		// split across params (e.g., ?w1=abandon&w2=abandon&...&w12=about).
		// orderedQueryConcat joins without separators (for regex DLP), so we
		// build a space-separated version for seed word tokenization.
		if parsed.RawQuery != "" && strings.Contains(parsed.RawQuery, "&") {
			var seedConcat strings.Builder
			for i, pair := range strings.Split(parsed.RawQuery, "&") {
				_, value, _ := strings.Cut(pair, "=")
				if value != "" {
					if i > 0 {
						seedConcat.WriteByte(' ')
					}
					seedConcat.WriteString(IterativeDecode(value))
				}
			}
			seedTargets = append(seedTargets, dlpTarget{seedConcat.String(), "query_concat:url_decoded"})
		}
		// Decoded path segments: base64/hex/base32 encoded seed phrases in path.
		for _, seg := range strings.Split(parsed.Path, "/") {
			if len(seg) < 20 {
				continue
			}
			for _, d := range decodeEncodingsRecursive(IterativeDecode(seg)) {
				seedTargets = append(seedTargets, dlpTarget{d.text, spanViewLabel(d.encoding+"_decoded", "url_path_segment")})
			}
		}
		// Hostname labels: catch seed words as subdomain labels
		// (e.g., "abandon.abandon.abandon...evil.com" exfils via DNS).
		// Join labels with spaces so the tokenizer sees them as words.
		hostname := parsed.Hostname()
		if strings.Contains(hostname, ".") {
			seedTargets = append(seedTargets, dlpTarget{strings.ReplaceAll(hostname, ".", " "), "hostname_labels_joined"})
		}
		// Path segments: catch seed words as path components
		// (e.g., "/abandon/abandon/abandon/.../about").
		if strings.Contains(parsed.Path, "/") {
			seedTargets = append(seedTargets, dlpTarget{strings.ReplaceAll(parsed.Path, "/", " "), spanViewLabel("slash_joined", "url_path")})
		}
		for _, target := range seedTargets {
			if target.text == "" {
				continue
			}
			if matches := seedprotect.DetectSpans(target.text, s.seedMinWords, s.seedVerifyChecksum); len(matches) > 0 {
				match := matches[0]
				patternName := "BIP-39 Seed Phrase"
				return Result{
					Allowed: false,
					Reason:  "DLP match: " + patternName + " (critical)",
					Scanner: ScannerDLP,
					Score:   1.0,
					spans: []MatchSpan{
						newMatchSpan(match.Start, match.End, target.viewLabel, patternName, "", ""),
					},
				}, warnMatches
			}
		}
	}

	// Check for environment variable leaks
	if result := s.checkSecretsInURL(s.envSecrets, parsed, "environment variable leak detected"); !result.Allowed {
		return result, warnMatches
	}

	// Check for known file secret leaks
	if result := s.checkSecretsInURL(s.fileSecrets, parsed, "known secret leak detected"); !result.Allowed {
		return result, warnMatches
	}

	return Result{Allowed: true}, deduplicateWarnMatches(warnMatches)
}

// querySubsequenceDLP checks ordered subsequences (combinations) of query
// parameter values for DLP pattern matches. Catches secrets split across
// multiple parameters with arbitrary junk values interleaved between fragments.
// Tries subsequences of size 2-4 for URLs with 3-20 query params.
// Cost: O(n^4) worst case, bounded at ~6k combinations for n=20.
func (s *Scanner) querySubsequenceDLP(rawQuery, hostname string) (Result, []WarnMatch) {
	if rawQuery == "" || !strings.Contains(rawQuery, "&") {
		return Result{Allowed: true}, nil
	}

	var values []string
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			values = append(values, IterativeDecode(value))
		}
	}

	n := len(values)
	if n < 3 {
		return Result{Allowed: true}, nil
	}
	// Cap to first 20 values to bound combinatorial cost (O(n^4)).
	if n > 20 {
		values = values[:20]
		n = 20
	}

	var warnMatches []WarnMatch
	for size := 2; size <= 4 && size <= n; size++ {
		result, warns := s.checkDLPCombinations(values, n, size, hostname)
		warnMatches = append(warnMatches, warns...)
		if !result.Allowed {
			return result, warnMatches
		}
	}

	return Result{Allowed: true}, warnMatches
}

// checkDLPCombinations generates all ordered combinations of the given size
// from the values slice and checks each concatenation against DLP patterns.
func (s *Scanner) checkDLPCombinations(values []string, n, size int, hostname string) (Result, []WarnMatch) {
	var warnMatches []WarnMatch
	indices := make([]int, size)
	for i := range indices {
		indices[i] = i
	}

	for {
		var b strings.Builder
		for _, idx := range indices {
			b.WriteString(values[idx])
		}
		concat := b.String()

		candidates := []struct {
			text      string
			viewLabel string
		}{
			{concat, dlpViewLabel("query_subsequence")},
		}
		for _, d := range decodeEncodingsRecursive(concat) {
			candidates = append(candidates, struct {
				text      string
				viewLabel string
			}{d.text, dlpViewLabel(d.encoding)})
		}

		for _, candidate := range candidates {
			cleaned := normalize.ForDLP(candidate.text)

			for _, idx := range s.dlpPreFilter.patternsToCheck(cleaned) {
				p := s.dlpPatterns[idx]
				if start, end, ok := p.matchSpan(cleaned); ok {
					if len(p.exemptDomains) > 0 && matchesDomainList(hostname, p.exemptDomains) {
						continue
					}
					span := newMatchSpan(start, end, candidate.viewLabel, p.name, p.bundle, p.bundleVersion)
					if p.warn {
						warnMatches = append(warnMatches, WarnMatch{
							PatternName: p.name,
							Severity:    p.severity,
							span:        span,
						})
						continue
					}
					return Result{
						Allowed: false,
						Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
						Scanner: ScannerDLP,
						Score:   1.0,
						spans:   []MatchSpan{span},
					}, warnMatches
				}
			}
		}

		if !nextCombination(indices, n) {
			break
		}
	}

	return Result{Allowed: true}, warnMatches
}

// nextCombination advances indices to the next lexicographic combination.
// Returns false when all combinations have been exhausted.
func nextCombination(indices []int, n int) bool {
	k := len(indices)
	for i := k - 1; i >= 0; i-- {
		if indices[i] < n-k+i {
			indices[i]++
			for j := i + 1; j < k; j++ {
				indices[j] = indices[j-1] + 1
			}
			return true
		}
	}
	return false
}

// emitDLPWarns calls the instance warn hook for each warn match if set.
func (s *Scanner) emitDLPWarns(ctx context.Context, matches []WarnMatch) {
	hook := s.getDLPWarnHook()
	if len(matches) == 0 || hook == nil {
		return
	}
	for _, m := range matches {
		hook(ctx, m.PatternName, m.Severity)
	}
}

// deduplicateWarnMatches removes duplicate warn matches by pattern name.
func deduplicateWarnMatches(matches []WarnMatch) []WarnMatch {
	if len(matches) <= 1 {
		return matches
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]WarnMatch, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m.PatternName]; !ok {
			seen[m.PatternName] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

// checkSecretsInURL scans a URL for leaked secrets (env vars or file-based).
// It URL-decodes, strips control chars, and checks all encoded forms of each secret.
func (s *Scanner) checkSecretsInURL(secrets []string, parsed *url.URL, reasonPrefix string) Result {
	if len(secrets) == 0 {
		return Result{Allowed: true}
	}

	fullURL := normalize.StripControlChars(parsed.String())
	decodedURL := normalize.StripControlChars(IterativeDecode(fullURL))
	texts := []spanTextView{
		{text: fullURL, viewLabel: "control_stripped_url"},
		{text: decodedURL, viewLabel: "control_stripped_url:url_decoded"},
	}
	lowerTexts := []spanTextView{
		{text: strings.ToLower(fullURL), viewLabel: lowerViewLabel("control_stripped_url")},
		{text: strings.ToLower(decodedURL), viewLabel: lowerViewLabel("control_stripped_url:url_decoded")},
	}

	for _, secret := range secrets {
		if matched, enc, start, end, viewLabel := matchSecretEncodingSpan(secret, texts, lowerTexts); matched {
			reason := reasonPrefix
			if enc != "" {
				reason += " (" + enc + "-encoded)"
			}
			return Result{
				Allowed: false,
				Reason:  reason,
				Scanner: ScannerDLP,
				Score:   1.0,
				spans: []MatchSpan{
					newMatchSpan(start, end, viewLabel, reasonPrefix, "", ""),
				},
			}
		}
	}
	// Canary fallback: if no DLP pattern matched, check canary tokens.
	// This runs last so DLP patterns get attribution priority.
	if matches := s.scanCanaryText(parsed.String()); len(matches) > 0 {
		m := matches[0]
		reason := fmt.Sprintf("DLP match: %s (%s)", m.PatternName, m.Severity)
		if m.Encoded != "" {
			reason += " [" + m.Encoded + "]"
		}
		return Result{
			Allowed: false,
			Reason:  reason,
			Scanner: ScannerDLP,
			Score:   1.0,
			spans:   []MatchSpan{m.Span()},
		}
	}

	return Result{Allowed: true}
}

type spanTextView struct {
	text      string
	viewLabel string
}

func indexAnyView(needle string, views []spanTextView) (int, int, string, bool) {
	for _, view := range views {
		if start := strings.Index(view.text, needle); start >= 0 {
			return start, start + len(needle), view.viewLabel, true
		}
	}
	return 0, 0, "", false
}

func indexEncodedTokenView(needle string, views []spanTextView, kind encodedTokenKind) (int, int, string, bool) {
	if len(needle) == 0 {
		return 0, 0, "", false
	}
	for _, view := range views {
		text := view.text
		for start := 0; start < len(text); start++ {
			if text[start] != needle[0] {
				continue
			}
			textIdx := start
			needleIdx := 0
			for textIdx < len(text) && needleIdx < len(needle) {
				c := text[textIdx]
				if c == needle[needleIdx] {
					textIdx++
					needleIdx++
					continue
				}
				if isEncodedTokenSeparator(c, kind) {
					textIdx++
					continue
				}
				break
			}
			if needleIdx == len(needle) {
				return start, textIdx, view.viewLabel, true
			}
		}
	}
	return 0, 0, "", false
}

func matchSecretEncodingSpan(secret string, texts, lowerTexts []spanTextView) (bool, string, int, int, string) {
	// Raw match.
	if start, end, viewLabel, ok := indexAnyView(secret, texts); ok {
		return true, "", start, end, viewLabel
	}

	// Base64 standard (padded + unpadded).
	b64Std := base64.StdEncoding.EncodeToString([]byte(secret))
	b64StdNoPad := strings.TrimRight(b64Std, "=")
	if start, end, viewLabel, ok := indexAnyView(b64Std, texts); ok {
		return true, encodingBase64, start, end, viewLabel
	}
	if b64StdNoPad != b64Std {
		if start, end, viewLabel, ok := indexAnyView(b64StdNoPad, texts); ok {
			return true, encodingBase64, start, end, viewLabel
		}
	}
	if start, end, viewLabel, ok := indexEncodedTokenView(b64Std, texts, encodedTokenBase64Std); ok {
		return true, encodingBase64, start, end, viewLabel
	}
	if b64StdNoPad != b64Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64StdNoPad, texts, encodedTokenBase64Std); ok {
			return true, encodingBase64, start, end, viewLabel
		}
	}

	// Base64 URL-safe (padded + unpadded).
	b64URL := base64.URLEncoding.EncodeToString([]byte(secret))
	b64URLNoPad := strings.TrimRight(b64URL, "=")
	if b64URL != b64Std {
		if start, end, viewLabel, ok := indexAnyView(b64URL, texts); ok {
			return true, "base64url", start, end, viewLabel
		}
	}
	if b64URLNoPad != b64StdNoPad {
		if start, end, viewLabel, ok := indexAnyView(b64URLNoPad, texts); ok {
			return true, "base64url", start, end, viewLabel
		}
	}
	if b64URL != b64Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64URL, texts, encodedTokenBase64URL); ok {
			return true, "base64url", start, end, viewLabel
		}
	}
	if b64URLNoPad != b64StdNoPad {
		if start, end, viewLabel, ok := indexEncodedTokenView(b64URLNoPad, texts, encodedTokenBase64URL); ok {
			return true, "base64url", start, end, viewLabel
		}
	}

	// Hex (case-insensitive via pre-lowered texts).
	hexEnc := hex.EncodeToString([]byte(secret))
	if start, end, viewLabel, ok := indexAnyView(hexEnc, lowerTexts); ok {
		return true, encodingHex, start, end, viewLabel
	}

	// Delimiter-separated hex variants for env/file secret detection.
	// Matches all formats that normalizeHex can strip.
	colonHex := hexByteSep(hexEnc, ":")
	spaceHex := hexByteSep(hexEnc, " ")
	hyphenHex := hexByteSep(hexEnc, "-")
	commaHex := hexByteSep(hexEnc, ",")
	bsxHex := hexBytePrefix(hexEnc, `\x`)
	zxHex := hexBytePrefix(hexEnc, "0x")
	for _, candidate := range []string{colonHex, spaceHex, hyphenHex, commaHex, bsxHex, zxHex} {
		if start, end, viewLabel, ok := indexAnyView(candidate, lowerTexts); ok {
			return true, encodingHex, start, end, viewLabel
		}
	}

	// Base32 standard (padded + unpadded).
	b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
	b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	if start, end, viewLabel, ok := indexAnyView(b32Std, texts); ok {
		return true, encodingBase32, start, end, viewLabel
	}
	if b32NoPad != b32Std {
		if start, end, viewLabel, ok := indexAnyView(b32NoPad, texts); ok {
			return true, encodingBase32, start, end, viewLabel
		}
	}
	if start, end, viewLabel, ok := indexEncodedTokenView(b32Std, texts, encodedTokenBase32); ok {
		return true, encodingBase32, start, end, viewLabel
	}
	if b32NoPad != b32Std {
		if start, end, viewLabel, ok := indexEncodedTokenView(b32NoPad, texts, encodedTokenBase32); ok {
			return true, encodingBase32, start, end, viewLabel
		}
	}

	return false, "", 0, 0, ""
}

// nonSecretEnvNames lists environment variable names that are never secrets.
// These are well-known system/shell/runtime variables whose values (paths,
// locale strings, color codes) routinely exceed the length and entropy
// thresholds but carry zero secret content. Skipping them prevents false
// positives when agents legitimately send values like $PWD in tool arguments.
var nonSecretEnvNames = map[string]struct{}{
	// Working directory and paths
	"PWD": {}, "OLDPWD": {}, "HOME": {}, "PATH": {},
	"TMPDIR": {}, "TEMP": {}, "TMP": {},
	// POSIX "last command" variable - bash sets $_ to the absolute path
	// of the previously executed command. High-entropy binary path leaks
	// into scans whenever the parent shell ran something like
	// /usr/local/bin/go test. Not a secret, never has been.
	"_": {},
	// User identity (public, not secret)
	"USER": {}, "LOGNAME": {}, "USERNAME": {}, "HOSTNAME": {}, "HOST": {},
	// Shell and terminal
	"SHELL": {}, "SHLVL": {}, "TERM": {}, "TERM_PROGRAM": {},
	"COLORTERM": {}, "COLORFGBG": {},
	// Locale
	"LANG": {}, "LANGUAGE": {},
	// Display
	"DISPLAY": {}, "WAYLAND_DISPLAY": {},
	// Editor
	"EDITOR": {}, "VISUAL": {}, "PAGER": {}, "LESS": {},
	// Color codes (LS_COLORS is often very long and high-entropy)
	"LS_COLORS": {}, "LSCOLORS": {},
	// D-Bus / SSH agent (socket paths, not credentials)
	"DBUS_SESSION_BUS_ADDRESS": {}, "SSH_AUTH_SOCK": {},
	// Public GitHub Actions metadata URLs. These values are fixed service
	// endpoints, not credentials, and frequently appear in legitimate traffic.
	"GITHUB_API_URL": {}, "GITHUB_GRAPHQL_URL": {}, "GITHUB_SERVER_URL": {},
	// Language runtimes (paths, not secrets)
	"GOPATH": {}, "GOROOT": {}, "GOBIN": {},
	"PYTHONPATH": {}, "PYTHONHOME": {}, "NODE_PATH": {},
	"MANPATH": {}, "INFOPATH": {},
	// Prompt strings
	"PS1": {}, "PS2": {}, "PS3": {}, "PS4": {},
	// Windows equivalents (matched case-insensitively via ToUpper)
	"USERPROFILE": {}, "APPDATA": {}, "LOCALAPPDATA": {},
	"PROGRAMFILES": {}, "PROGRAMDATA": {},
	"SYSTEMROOT": {}, "WINDIR": {}, "COMSPEC": {},
	"COMPUTERNAME": {}, "PATHEXT": {}, "SESSIONNAME": {},
}

// nonSecretEnvPrefixes lists prefixes for env var names that are never secrets.
// Matched against the uppercased variable name (case-insensitive).
var nonSecretEnvPrefixes = []string{
	"LC_",  // LC_ALL, LC_CTYPE, LC_MESSAGES, etc.
	"XDG_", // XDG_DATA_HOME, XDG_RUNTIME_DIR, etc.
}

// isNonSecretEnvName returns true if the environment variable name is a
// well-known non-secret variable that should be excluded from leak detection.
// Comparison is case-insensitive: on Windows, env var names like "Path" and
// "UserProfile" are common mixed-case variants of the uppercase originals.
func isNonSecretEnvName(name string) bool {
	upper := strings.ToUpper(name)
	if _, ok := nonSecretEnvNames[upper]; ok {
		return true
	}
	for _, prefix := range nonSecretEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// envLeakMinEntropy is the Shannon-entropy floor (bits/char) above which an
// env-variable value is treated as secret-shaped. Single source of truth shared
// by extractEnvSecrets (whole-value filter) and looksLikeOpaqueToken (per-segment
// guard) so the two stay consistent.
const envLeakMinEntropy = 3.0

// minOpaqueTokenLen is the component length at or above which a single-component,
// slash-prefixed colon-list segment is treated as a possible opaque secret token
// rather than a short directory name. Short PATH dirs (/bin, /sbin, /opt) fall
// below it and stay recognised as path components.
const minOpaqueTokenLen = 16

// looksLikeOpaqueToken reports whether a colon-list segment (already known to
// begin with "/") is shaped like an opaque secret token rather than a directory
// component. A genuine directory entry is either multi-component (/usr/local/bin,
// has an inner separator) or a short name (/bin, /sbin); a smuggled token is a
// single long, high-entropy blob (/K7MDENGbPxRfiCYzQ). Used to stop a PATH-like
// wrapper from skipping a value that the single-value branch would keep scannable.
func looksLikeOpaqueToken(seg string) bool {
	body := strings.TrimPrefix(seg, "/")
	if strings.Contains(body, "/") {
		return false // multi-component path, not a single opaque token
	}
	return len(body) >= minOpaqueTokenLen && ShannonEntropy(body) > envLeakMinEntropy
}

// isPathShapedValue reports whether an environment-variable value looks like a
// multi-component filesystem path (or a colon-separated list of paths) rather
// than a secret. extractEnvSecrets uses it to keep path-valued variables out of
// the env-leak matcher set: a path the agent references during normal operation
// is not an exfiltrated secret, and a deep directory path carries enough Shannon
// entropy to slip past the entropy filter and become a spurious matcher.
// Matching is on value SHAPE, not variable name, because the name skip-list is
// incomplete — it misses HERMES_HOME, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, and
// any other path-valued variable a deployment introduces.
//
// Unix-path-shaped only: a multi-component value beginning with "/" or "~/", or
// a "/"-prefixed colon list (PATH, LD_LIBRARY_PATH). Windows drive paths are
// not recognised; pipelock's agent-containment target is Linux. Slash-prefixed
// opaque tokens are left in the matcher set, as are values containing '+' or '='
// because those are common in encoded secrets.
func isPathShapedValue(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	if strings.ContainsAny(v, "+=") {
		return false
	}

	// Colon-separated list where every element is an absolute path
	// (PATH-style). Checked first so multi-path lists aren't missed.
	if strings.Contains(v, ":") {
		for _, seg := range strings.Split(v, ":") {
			if seg == "" || !strings.HasPrefix(seg, "/") {
				return false
			}
			// A slash-prefixed opaque token riding in a PATH-like wrapper
			// (e.g. "/usr/bin:/K7MDENGbPxRfiCYzQ") must not be skipped: the
			// single-value branch keeps such tokens scannable, so the list
			// branch has to as well, or the wrapper becomes an exfil bypass.
			if looksLikeOpaqueToken(seg) {
				return false
			}
		}
		return true
	}

	// Single absolute or home-relative path. Require at least one directory
	// separator after the prefix so "/opaque-token-value" stays scannable.
	if strings.HasPrefix(v, "~/") {
		rest := strings.TrimPrefix(v, "~/")
		return strings.Contains(rest, "/") || strings.HasPrefix(rest, ".")
	}
	if strings.HasPrefix(v, "/") {
		return strings.Contains(strings.TrimPrefix(v, "/"), "/")
	}
	return false
}

// extractEnvSecrets filters environment variables for likely secrets.
// Returns values >= minLen chars with Shannon entropy >3.0.
// Skips well-known non-secret variable names (PWD, PATH, HOME, etc.) and
// path-shaped values (see isPathShapedValue) to avoid false positives on paths
// and locale strings.
func extractEnvSecrets(minLen int) []string {
	if minLen <= 0 {
		minLen = 16
	}

	var secrets []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		value := parts[1]

		// Skip well-known non-secret variables (paths, locale, shell config).
		if isNonSecretEnvName(name) {
			continue
		}

		// Skip path-shaped values regardless of variable name. Deep paths
		// carry high entropy and would otherwise become spurious matchers
		// that flag the agent's own normal path references as leaks.
		if isPathShapedValue(value) {
			continue
		}

		if len(value) < minLen {
			continue
		}

		if ShannonEntropy(value) > envLeakMinEntropy {
			secrets = append(secrets, value)
		}
	}

	return secrets
}

// dedupSecrets removes duplicates from fileSecrets: both against envSecrets
// (preventing double-scanning) and within fileSecrets itself.
func dedupSecrets(fileSecrets, envSecrets []string) []string {
	existing := make(map[string]struct{}, len(envSecrets)+len(fileSecrets))
	for _, s := range envSecrets {
		existing[s] = struct{}{}
	}
	var result []string
	for _, s := range fileSecrets {
		if _, ok := existing[s]; !ok {
			existing[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// LoadSecretsFile reads explicit secret values from a file, one per line.
// Lines starting with # (after optional whitespace) are comments.
// Blank lines, null-byte lines, and lines below minLen are skipped.
// Max 4096 bytes per line, max 1000 entries.
func LoadSecretsFile(path string, minLen int) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	const (
		maxLineLen = 4096
		maxEntries = 1000
	)

	var (
		secrets []string
		lineNum int
		first   = true
	)

	sc := bufio.NewScanner(f)
	// Buffer must exceed maxLineLen so bufio.ErrTooLong cannot fire for any
	// line the explicit len(line) > maxLineLen guard would skip.
	const scanBufMax = maxLineLen*2 + 4096
	sc.Buffer(make([]byte, 0, scanBufMax), scanBufMax)

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Strip UTF-8 BOM from first line.
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}

		// Strip leading and trailing whitespace/tabs/CR.
		line = strings.TrimSpace(line)

		// Skip blank lines.
		if line == "" {
			continue
		}

		// Skip comment lines (# as first non-whitespace).
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}

		// Reject lines with null bytes.
		if strings.ContainsRune(line, '\x00') {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d contains null byte, skipping\n", lineNum)
			continue
		}

		// Reject lines exceeding max length.
		if len(line) > maxLineLen {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d exceeds %d bytes, skipping\n", lineNum, maxLineLen)
			continue
		}

		// Skip values below minimum length.
		if len(line) < minLen {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d too short (%d < %d), skipping\n", lineNum, len(line), minLen)
			continue
		}

		// Enforce max entries.
		if len(secrets) >= maxEntries {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file exceeds %d entries, ignoring remainder\n", maxEntries)
			break
		}

		secrets = append(secrets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading secrets file: %w", err)
	}

	return secrets, nil
}

// buildPathEntropyExempt compiles a request_policy view used only to suppress
// path entropy on operator-governed paths. Compilation errors are config errors
// that config validation already rejects before New runs; if one slips through,
// return nil so path entropy stays fully active (fail secure, never fail open).
func buildPathEntropyExempt(cfg *config.Config) *reqpolicy.Matcher {
	m, err := reqpolicy.NewMatcher(&cfg.RequestPolicy)
	if err != nil {
		return nil
	}
	return m
}

// checkEntropy calculates Shannon entropy on URL path segments and query values.
// Domains listed in subdomain_entropy_exclusions skip path entropy checks only
// (APIs that use high-entropy subdomains often embed tokens in URL paths too).
// Domains listed in query_entropy_exclusions skip query parameter entropy
// checks only (well-known APIs whose contract embeds high-entropy material
// in query strings by design, e.g. S3 pre-signed URLs with X-Amz-Signature
// and response-content-disposition). The two lists are independent: a host
// listed only in subdomain_entropy_exclusions still has its query parameters
// scanned, and vice versa.
func (s *Scanner) checkEntropy(parsed *url.URL) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}

	hostname := parsed.Hostname()
	excludedPath := s.isExcludedFromSubdomainEntropy(hostname)
	excludedQuery := s.isExcludedFromQueryEntropy(hostname)

	// Path entropy is also skipped when the operator already governs this
	// exact host+path with a request_policy route (explicit host + path
	// constraints). The blunt entropy heuristic is redundant on paths the
	// operator inspects by rule, and it false-positives on legitimate
	// high-entropy REST resource ids. This is path-only: it never affects
	// query entropy (below), subdomain entropy, DLP, or SSRF.
	routeExemptPath := s.pathEntropyExempt.PathEntropyExempt(hostname, parsed.Path)

	// Check path segments (skipped for excluded domains).
	if !excludedPath && !routeExemptPath {
		for _, segment := range strings.Split(parsed.Path, "/") {
			if len(segment) >= s.entropyMinLen {
				entropy := ShannonEntropy(segment)
				if entropy > s.entropyThreshold {
					return Result{
						Allowed: false,
						Reason:  fmt.Sprintf("high entropy path segment (%.2f > %.2f threshold)", entropy, s.entropyThreshold),
						Scanner: ScannerEntropy,
						Score:   math.Min(entropy/8.0, 1.0), // normalize to 0-1
					}
				}
			}
		}
	}

	// Check query parameter keys and values. Query entropy exclusions skip
	// only the entropy heuristic; DB-URI SSRF guards still run because they
	// protect a separate network-control invariant.
	// Keys are checked too - secrets can be stuffed into parameter names.
	if strings.Contains(parsed.RawQuery, ";") {
		if result, blocked := s.scanAmbiguousRawQuery(parsed.RawQuery, !excludedQuery); blocked {
			return result
		}
	}
	for key, values := range parsed.Query() {
		if !excludedQuery && len(key) >= s.entropyMinLen {
			entropy := ShannonEntropy(key)
			if entropy > s.entropyThreshold {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("high entropy query key %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
					Scanner: ScannerEntropy,
					Score:   math.Min(entropy/8.0, 1.0),
				}
			}
		}
		for _, v := range values {
			if result, blocked := unsafeDatabaseURIQueryValueResult(v); blocked {
				return result
			}
			if !excludedQuery && len(v) >= s.entropyMinLen {
				entropy := ShannonEntropy(v)
				if shouldSkipQueryValueEntropy(v, entropy, s.entropyThreshold) {
					continue
				}
				if entropy > s.entropyThreshold {
					if s.isQueryEntropyParamExcluded(parsed, key) {
						continue
					}
					return Result{
						Allowed: false,
						Reason:  fmt.Sprintf("high entropy query param %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
						Scanner: ScannerEntropy,
						Score:   math.Min(entropy/8.0, 1.0),
					}
				}
			}
		}
	}

	return Result{Allowed: true}
}

func (s *Scanner) scanAmbiguousRawQuery(rawQuery string, scanEntropy bool) (Result, bool) {
	for _, pair := range strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == ';'
	}) {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, ok := strictQueryEntropyComponent(rawKey)
		if !ok {
			key = rawKey
		}
		value, ok := strictQueryEntropyComponent(rawValue)
		if !ok {
			value = rawValue
		}
		if scanEntropy && len(key) >= s.entropyMinLen {
			entropy := ShannonEntropy(key)
			if entropy > s.entropyThreshold {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("high entropy query key %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
					Scanner: ScannerEntropy,
					Score:   math.Min(entropy/8.0, 1.0),
				}, true
			}
		}
		if result, blocked := unsafeDatabaseURIQueryValueResult(value); blocked {
			return result, true
		}
		if !scanEntropy || len(value) < s.entropyMinLen {
			continue
		}
		entropy := ShannonEntropy(value)
		if shouldSkipQueryValueEntropy(value, entropy, s.entropyThreshold) {
			continue
		}
		if entropy > s.entropyThreshold {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("high entropy query param %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
				Scanner: ScannerEntropy,
				Score:   math.Min(entropy/8.0, 1.0),
			}, true
		}
	}
	return Result{}, false
}

func strictQueryEntropyComponent(raw string) (string, bool) {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", false
	}
	return decoded, true
}

type queryEntropyParamExclusionKey struct {
	scheme string
	host   string
	path   string
	param  string
}

func buildQueryEntropyParamExclusions(entries []config.QueryEntropyParamExclusion) map[queryEntropyParamExclusionKey]struct{} {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[queryEntropyParamExclusionKey]struct{}, len(entries))
	for _, entry := range entries {
		scheme := entry.Scheme
		if scheme == "" {
			scheme = config.QueryEntropyParamDefaultScheme
		}
		out[queryEntropyParamExclusionKey{
			scheme: strings.ToLower(scheme),
			host:   strings.TrimSuffix(strings.ToLower(entry.Host), "."),
			path:   entry.Path,
			param:  entry.Param,
		}] = struct{}{}
	}
	return out
}

func (s *Scanner) isQueryEntropyParamExcluded(parsed *url.URL, param string) bool {
	if len(s.queryParamExclusions) == 0 || parsed.User != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if !isDefaultEndpointPort(parsed, scheme) {
		return false
	}
	host, ok := canonicalQueryEntropyRuntimeHost(parsed.Hostname())
	if !ok {
		return false
	}
	key := queryEntropyParamExclusionKey{
		scheme: scheme,
		host:   host,
		path:   parsed.EscapedPath(),
		param:  param,
	}
	if _, ok := s.queryParamExclusions[key]; !ok {
		return false
	}
	return rawQueryHasSingleExactDecodedKey(parsed.RawQuery, param)
}

func canonicalQueryEntropyRuntimeHost(raw string) (string, bool) {
	host := strings.TrimSuffix(raw, ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	normalized := strings.TrimSuffix(strings.ToLower(ascii), ".")
	if !wellFormedQueryEntropyDNSHost(normalized) {
		return "", false
	}
	return normalized, true
}

func wellFormedQueryEntropyDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

func isDefaultEndpointPort(parsed *url.URL, scheme string) bool {
	port := parsed.Port()
	if port == "" {
		return true
	}
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	default:
		return false
	}
}

func rawQueryHasSingleExactDecodedKey(rawQuery, param string) bool {
	if strings.Contains(rawQuery, ";") {
		return false
	}
	count := 0
	for rawQuery != "" {
		pair := rawQuery
		if i := strings.IndexByte(rawQuery, '&'); i >= 0 {
			pair = rawQuery[:i]
			rawQuery = rawQuery[i+1:]
		} else {
			rawQuery = ""
		}
		rawKey, _, _ := strings.Cut(pair, "=")
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			return false
		}
		if decodedKey != param {
			continue
		}
		if rawKey != param {
			return false
		}
		count++
	}
	return count == 1
}

func isDatabaseURIScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "rediss":
		return true
	default:
		return false
	}
}

func unsafeDatabaseURIQueryValueResult(value string) (Result, bool) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Result{}, false
	}
	if !isDatabaseURIScheme(u.Scheme) {
		return Result{}, false
	}

	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseAlternativeIP(host)
	}
	if ip != nil {
		scannerLabel := ScannerSSRF
		reason := fmt.Sprintf("database URI query value points to IP literal host %s", host)
		if isCloudMetadataIP(ip) {
			scannerLabel = ScannerSSRFMetadata
			reason = fmt.Sprintf("database URI query value points to cloud metadata endpoint %s", host)
		}
		return Result{Allowed: false, Reason: reason, Scanner: scannerLabel, Score: 1.0}, true
	}
	if host == "metadata.google.internal" {
		return Result{
			Allowed: false,
			Reason:  "database URI query value points to cloud metadata hostname metadata.google.internal",
			Scanner: ScannerSSRFMetadata,
			Score:   1.0,
		}, true
	}
	return Result{}, false
}

func shouldSkipQueryValueEntropy(value string, entropy, threshold float64) bool {
	if entropy <= threshold || entropy > threshold+0.35 {
		return false
	}
	if isCredentiallessDatabaseURI(value, threshold) {
		return true
	}
	return isHumanReadableHyphenatedQueryValue(value)
}

func isCredentiallessDatabaseURI(value string, threshold float64) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if !isDatabaseURIScheme(u.Scheme) {
		return false
	}
	return isLowRiskDatabaseURIHost(u.Hostname(), threshold) && isLowRiskDatabaseURIPath(u.EscapedPath(), threshold)
}

func isLowRiskDatabaseURIHost(host string, threshold float64) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil || parseAlternativeIP(host) != nil {
		return false
	}
	switch host {
	case "metadata.google.internal":
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if len(label) >= 12 && ShannonEntropy(label) > threshold {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isLowRiskDatabaseURIPath(path string, threshold float64) bool {
	if path == "" || path == "/" {
		return true
	}
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if segment == "" || len(segment) > 32 {
			return false
		}
		if len(segment) >= 12 && ShannonEntropy(segment) > threshold {
			return false
		}
		for _, r := range segment {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
				continue
			}
			return false
		}
	}
	return true
}

func isHumanReadableHyphenatedQueryValue(value string) bool {
	if len(value) > 40 || !strings.Contains(value, "-") || strings.ContainsAny(value, "_+/=") {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) < 3 || len(parts) > 5 {
		return false
	}
	wordParts := 0
	yearParts := 0
	for _, part := range parts {
		if part == "" {
			return false
		}
		if isYearLike(part) {
			yearParts++
			if yearParts > 1 {
				return false
			}
			continue
		}
		if !isReadableLowerWord(part) {
			return false
		}
		wordParts++
	}
	return wordParts >= 3 && wordParts <= 4
}

func isYearLike(part string) bool {
	if len(part) != 4 {
		return false
	}
	for _, r := range part {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isReadableLowerWord(part string) bool {
	if len(part) < 3 || len(part) > 12 {
		return false
	}
	hasVowel := false
	consonantRun := 0
	for _, r := range part {
		if r < 'a' || r > 'z' {
			return false
		}
		if strings.ContainsRune("aeiouy", r) {
			hasVowel = true
			consonantRun = 0
			continue
		}
		consonantRun++
		if consonantRun > 4 {
			return false
		}
	}
	return hasVowel
}

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// English text: ~3.5-4.0, base64: ~5.5-6.0, hex: ~4.0, encrypted: ~7.5-8.0.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, ch := range s {
		freq[ch]++
		total++
	}

	entropy := 0.0
	length := float64(total)
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// checkDataBudget enforces per-domain data transfer limits.
// Uses baseDomain normalization to prevent subdomain rotation bypass.
func (s *Scanner) checkDataBudget(hostname string) Result {
	if s.dataBudget == nil {
		return Result{Allowed: true}
	}
	domain := baseDomain(hostname)
	if !s.dataBudget.IsAllowed(domain) {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("data budget exceeded for %s", hostname),
			Scanner: ScannerDataBudget,
			Score:   0.8,
		}
	}
	return Result{Allowed: true}
}

// subdomainMinLabelLen is the minimum subdomain label length to check.
// Short labels (www, api, cdn) are normal and should not be flagged.
const subdomainMinLabelLen = 8

// Hostname-exfiltration heuristics. These catch DNS tunneling / exfiltration
// that the Shannon-entropy gate misses: hex labels top out at 4.0 bits/char
// (16 symbols), so a secret hex-encoded into a subdomain measures ~3.1 and
// never exceeds a 4.0 threshold. Two structural signals close that gap.
const (
	subdomainEncodedLabelReasonPrefix  = "encoded data in subdomain label"
	subdomainEncodedChunksReasonPrefix = "subdomain payload chunked across"

	// subdomainEncodedMinLen is the minimum length for a single subdomain
	// label to be flagged as encoded data when it is entirely hex or base32.
	// Set above typical short commit-SHA prefixes (7-12 chars) to limit false
	// positives on preview-deploy hostnames; operators with longer encoded
	// subdomains use subdomain_entropy_exclusions.
	subdomainEncodedMinLen = 14

	// Signal B flags DNS tunneling that chunks encoded data across several
	// labels (each individually low-entropy). It fires on either many encoded
	// chunks alone, or fewer chunks stacked in a deep hostname. Two short hash
	// labels in a shallow host (deadbeef.cafebabe.preview.example.com) stay
	// below both thresholds, and dictionary/hyphenated labels are never counted
	// as chunks. A chunk is a hex/base32 label >= subdomainChunkMinLen chars.
	subdomainExfilMinLabels  = 3 // outer gate: at least this many subdomain labels
	subdomainExfilManyChunks = 3 // clause 1: this many encoded chunks, any depth
	subdomainExfilDeepLabels = 4 // clause 2: this many subdomain labels …
	subdomainExfilDeepChunks = 2 // … carrying at least this many encoded chunks
	subdomainChunkMinLen     = 8
)

// isHexLabel reports whether s consists entirely of hexadecimal characters.
func isHexLabel(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// base32MinDigits is the minimum number of base32 digit characters (2-7) a
// label must contain to be treated as encoded data. Real base32 data is ~19%
// digits, so a 16+ char token almost always carries several; requiring two
// avoids flagging ordinary words that happen to contain a single digit.
const base32MinDigits = 2

// isBase32Label reports whether s is an RFC 4648 base32 token. Matching is
// case-insensitive because hostnames are lowercased in transit (DNS is
// case-insensitive). At least base32MinDigits digit chars (2-7) must be present
// so ordinary words are not treated as encoded data.
func isBase32Label(s string) bool {
	digits := 0
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '2' && r <= '7':
			digits++
		default:
			return false
		}
	}
	return digits >= base32MinDigits
}

// isEncodedExfilLabel reports whether a subdomain label looks like a chunk of
// hex- or base32-encoded data long enough to carry an exfiltrated secret.
func isEncodedExfilLabel(label string) bool {
	if len(label) < subdomainEncodedMinLen {
		return false
	}
	return isHexLabel(label) || isBase32Label(label)
}

// looksEncodedChunk reports whether a subdomain label looks like one chunk of
// encoded data split across several labels (the DNS-tunneling shape). Shorter
// than isEncodedExfilLabel's single-label threshold because tunneling spreads
// the payload over many small labels.
func looksEncodedChunk(label string) bool {
	if len(label) < subdomainChunkMinLen {
		return false
	}
	return isHexLabel(label) || isBase32Label(label)
}

// checkSubdomainEntropy flags hostnames where subdomain labels contain
// high-entropy data, indicating base64/hex exfiltration via DNS queries.
// Only checks hostnames with 3+ labels (at least one subdomain beyond base domain).
// Excludes domains listed in subdomainExclusions (e.g., RunPod, cloud services
// that use high-entropy subdomains for legitimate purposes).
// Uses a separate threshold from query parameter entropy because subdomains
// have different baseline entropy - hex labels at 3.5-4.0 are suspicious
// in subdomains but common in query parameters.
func (s *Scanner) checkSubdomainEntropy(hostname string) Result {
	if s.subdomainEntropyThreshold <= 0 {
		return Result{Allowed: true}
	}
	hostname = strings.TrimSuffix(hostname, ".")

	// Skip IP addresses
	if net.ParseIP(hostname) != nil {
		return Result{Allowed: true}
	}

	// Skip domains on the exclusion list (exact match or wildcard suffix)
	if s.isExcludedFromSubdomainEntropy(hostname) {
		return Result{Allowed: true}
	}

	regDomain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil || regDomain == hostname {
		return Result{Allowed: true}
	}
	subdomainPart := strings.TrimSuffix(hostname, "."+regDomain)
	subdomainPart = strings.TrimSuffix(subdomainPart, ".")
	if subdomainPart == "" {
		return Result{Allowed: true}
	}
	// Subdomain labels carry the exfiltration payload; the registrable domain does not.
	subLabels := strings.Split(subdomainPart, ".")

	// Check all subdomain labels for high Shannon entropy.
	for _, label := range subLabels {
		if len(label) < subdomainMinLabelLen {
			continue
		}
		entropy := ShannonEntropy(label)
		if entropy > s.subdomainEntropyThreshold {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("high entropy subdomain label %q (%.2f > %.2f threshold)", label, entropy, s.subdomainEntropyThreshold),
				Scanner: ScannerSubdomainEntropy,
				Score:   math.Min(entropy/8.0, 1.0),
			}
		}
	}

	// Signal A: a single long hex/base32 label. Encoded secrets in subdomains
	// sit at or below the entropy threshold (hex maxes at 4.0 bits/char), so
	// the entropy loop above misses them.
	for _, label := range subLabels {
		if isEncodedExfilLabel(label) {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("%s %q (possible DNS exfiltration)", subdomainEncodedLabelReasonPrefix, label),
				Scanner: ScannerSubdomainEntropy,
				Score:   0.85,
			}
		}
	}

	// Signal B: data chunked across several subdomain labels. Each chunk may be
	// individually low-entropy, so the entropy loop above misses them; the
	// signal is the structure — multiple encoded-looking labels stacked in one
	// hostname. Requiring several encoded chunks (not just length) avoids
	// flagging benign deep hostnames with dictionary or hyphenated labels.
	if len(subLabels) >= subdomainExfilMinLabels {
		encoded := 0
		for _, label := range subLabels {
			if looksEncodedChunk(label) {
				encoded++
			}
		}
		// Either many encoded chunks at any depth, or fewer chunks stacked in a
		// deep hostname. A shallow host with two short hash labels stays clean.
		manyChunks := encoded >= subdomainExfilManyChunks
		deepChunks := encoded >= subdomainExfilDeepChunks && len(subLabels) >= subdomainExfilDeepLabels
		if manyChunks || deepChunks {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("%s %d encoded labels of %d (possible DNS exfiltration)", subdomainEncodedChunksReasonPrefix, encoded, len(subLabels)),
				Scanner: ScannerSubdomainEntropy,
				Score:   0.8,
			}
		}
	}

	return Result{Allowed: true}
}

// matchesDomainList checks if the hostname matches any entry in a domain list.
// Supports exact hostnames and wildcard prefixes (*.example.com matches
// any subdomain of example.com, including example.com itself).
// All comparisons are case-insensitive with trailing-dot normalization.
func matchesDomainList(hostname string, domains []string) bool {
	host := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, pattern := range domains {
		// Defensive: patterns should already be normalized by config.Validate(),
		// but we re-normalize here as defense-in-depth for security-sensitive matching.
		p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
		if p == "" {
			continue
		}
		// Wildcard prefix: *.example.com matches sub.example.com and example.com
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			base := p[2:]   // "example.com"
			if host == base || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		// Exact match
		if host == p {
			return true
		}
	}
	return false
}

// isExcludedFromSubdomainEntropy checks if the hostname matches any subdomain
// entropy exclusion rule.
func (s *Scanner) isExcludedFromSubdomainEntropy(hostname string) bool {
	return matchesDomainList(hostname, s.subdomainExclusions)
}

// isExcludedFromQueryEntropy checks if the hostname matches any query entropy
// exclusion rule. Independent from subdomain entropy exclusion; both lists can
// be set or unset per host without affecting the other gate.
func (s *Scanner) isExcludedFromQueryEntropy(hostname string) bool {
	return matchesDomainList(hostname, s.queryExclusions)
}

// baseDomain returns the registrable domain (eTLD+1) for budget tracking,
// stripping subdomains to prevent bypass via subdomain rotation.
// Uses the Mozilla Public Suffix List via golang.org/x/net/publicsuffix,
// which correctly handles ccTLDs (co.uk, com.au, gov.uk, etc.).
// IP addresses and single-label hosts are returned as-is.
func baseDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// Fallback for single-label hosts (localhost, etc.)
		return hostname
	}
	return etld1
}

// MatchDomain checks if a hostname matches a pattern.
// Supports wildcard patterns like "*.example.com" which matches
// "sub.example.com", "a.b.example.com", and "example.com" itself.
// IP addresses only support exact match - wildcards are not applied to IPs
// to prevent false matches like "*.168.1.1" matching "192.168.1.1".
func MatchDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))

	// IP addresses: exact match only, no wildcard expansion.
	// Dots in IPs are not domain separators - "192" is not a subdomain of "168.1.1".
	if net.ParseIP(hostname) != nil {
		return hostname == pattern
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		base := pattern[2:]   // "example.com"
		return hostname == base || strings.HasSuffix(hostname, suffix)
	}
	return hostname == pattern
}
