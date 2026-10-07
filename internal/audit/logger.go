// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package audit provides structured JSON audit logging for all Pipelock events.
package audit

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/rs/zerolog"
)

const responseScanExemptFullTrustEffect = "response_scanning.exempt_domains is a full-trust valve: injection scanning is disabled for ALL responses from this host, including oversized over-cap responses that stream unscanned"

// WebSocket frame direction constants used in audit log entries.
const (
	DirectionClientToServer = "client_to_server"
	DirectionServerToClient = "server_to_client"
)

// Scanner label for DLP audit events (used in technique mapping).
const ScannerDLP = "dlp"

// actionBlock mirrors config.ActionBlock without importing the config package
// (which would create a dependency cycle). Used for emit severity mapping.
const actionBlock = "block"

// Severity constants mirroring config.Severity* to avoid a dependency cycle.
const (
	severityCritical = "critical"
	severityWarn     = "warn"
)

// BundleRuleHit records which community bundle rule triggered a detection.
// Included in audit events and webhook payloads when bundle rules match.
type BundleRuleHit struct {
	RuleID        string `json:"rule_id"`
	Bundle        string `json:"bundle"`
	BundleVersion string `json:"bundle_version"`
}

// Logger handles structured audit logging using zerolog.
type Logger struct {
	zl                 zerolog.Logger
	includeAllowed     bool
	includeBlocked     bool
	fileHandle         *os.File      // non-nil if logging to file
	filePath           string        // non-empty if logging to file
	fileCreated        bool          // true when this logger created filePath
	emitter            *emit.Emitter // optional external event emitter
	identifierRedactor *lazyIdentifierRedactor
	correlation        CorrelationID // per-request tag for emitted events; see WithCorrelation
}

// New creates a new audit logger. The caller should call Close when done.
func New(format, output, filePath string, includeAllowed, includeBlocked bool) (*Logger, error) {
	return newLogger(loggerOpts{
		IdentifierEntropyLoggerOpts: IdentifierEntropyLoggerOpts{
			Format:         format,
			Output:         output,
			FilePath:       filePath,
			IncludeAllowed: includeAllowed,
			IncludeBlocked: includeBlocked,
			Stream:         os.Stdout,
		},
		identifierSource: sharedIdentifierRedactor,
	})
}

// NewDurableFile creates an audit logger for an operation that must refuse to
// proceed unless it has a regular local file sink. It deliberately does not
// change New's behavior because the running server may use stream devices for
// its ordinary logging configuration.
func NewDurableFile(format, filePath string, includeAllowed, includeBlocked bool) (*Logger, error) {
	cleanPath := filepath.Clean(filePath)
	file, created, err := openDurableAuditFile(cleanPath)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat audit log file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("audit log file must be a regular file; set logging.file to a writable regular file: %s", cleanPath)
	}
	if err := validateDurableAuditPath(info, cleanPath); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync audit log file: %w", err)
	}
	if err := syncDurableAuditParent(cleanPath); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("sync audit log directory: %w", err)
	}
	logger, err := newLogger(loggerOpts{
		IdentifierEntropyLoggerOpts: IdentifierEntropyLoggerOpts{
			Format:         format,
			Output:         "file",
			FilePath:       cleanPath,
			IncludeAllowed: includeAllowed,
			IncludeBlocked: includeBlocked,
			Stream:         os.Stdout,
		},
		identifierSource: sharedIdentifierRedactor,
		openedFile:       file,
		fileCreated:      created,
	})
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return logger, nil
}

// NewWithStream creates an audit logger whose stream output uses stream rather
// than process stdout. Protocols that reserve stdout for framing, such as MCP
// stdio, use this to send local audit records to stderr without corrupting the
// protocol stream.
func NewWithStream(format, output, filePath string, includeAllowed, includeBlocked bool, stream io.Writer) (*Logger, error) {
	return newLogger(loggerOpts{
		IdentifierEntropyLoggerOpts: IdentifierEntropyLoggerOpts{
			Format:         format,
			Output:         output,
			FilePath:       filePath,
			IncludeAllowed: includeAllowed,
			IncludeBlocked: includeBlocked,
			Stream:         stream,
		},
		identifierSource: sharedIdentifierRedactor,
	})
}

// IdentifierEntropyLoggerOpts configures an audit logger with an explicit
// entropy source for runtime availability tests.
type IdentifierEntropyLoggerOpts struct {
	Format         string
	Output         string
	FilePath       string
	IncludeAllowed bool
	IncludeBlocked bool
	Stream         io.Writer
	Entropy        io.Reader
}

// NewWithIdentifierEntropy is NewWithStream with an explicit entropy source.
// Production loggers use the process-wide cryptographic source instead.
func NewWithIdentifierEntropy(opts IdentifierEntropyLoggerOpts) (*Logger, error) {
	return newLogger(loggerOpts{
		IdentifierEntropyLoggerOpts: opts,
		identifierSource: func() (*identifierRedactor, error) {
			if opts.Entropy == nil {
				return nil, errors.New("initialize audit identifier redaction: entropy reader is nil")
			}
			return newIdentifierRedactorFrom(opts.Entropy)
		},
	})
}

type loggerOpts struct {
	IdentifierEntropyLoggerOpts
	identifierSource func() (*identifierRedactor, error)
	openedFile       *os.File
	fileCreated      bool
}

func newLogger(opts loggerOpts) (*Logger, error) {
	if opts.Stream == nil {
		return nil, errors.New("create audit logger: stream writer is nil")
	}
	var writers []io.Writer

	if opts.Output == "stdout" || opts.Output == "both" {
		if opts.Format == "text" {
			writers = append(writers, zerolog.ConsoleWriter{Out: opts.Stream, TimeFormat: time.RFC3339})
		} else {
			writers = append(writers, opts.Stream)
		}
	}

	var fileHandle *os.File
	var fileCreated bool
	if opts.Output == "file" || opts.Output == "both" {
		f := opts.openedFile
		if f == nil {
			filePath := filepath.Clean(opts.FilePath)
			var err error
			f, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			fileCreated = err == nil
			if errors.Is(err, fs.ErrExist) {
				f, err = os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0o600)
			}
			if err != nil {
				return nil, err
			}
		} else {
			fileCreated = opts.fileCreated
		}
		writers = append(writers, f)
		fileHandle = f
	}

	if len(writers) == 0 {
		writers = append(writers, opts.Stream)
	}

	var w io.Writer
	if len(writers) == 1 {
		w = writers[0]
	} else {
		w = zerolog.MultiLevelWriter(writers...)
	}

	zl := zerolog.New(w).With().
		Timestamp().
		Str("component", "pipelock").
		Logger()

	filePath := ""
	if fileHandle != nil {
		filePath = filepath.Clean(opts.FilePath)
	}
	return &Logger{
		zl:                 zl,
		includeAllowed:     opts.IncludeAllowed,
		includeBlocked:     opts.IncludeBlocked,
		fileHandle:         fileHandle,
		filePath:           filePath,
		fileCreated:        fileCreated,
		identifierRedactor: newLazyIdentifierRedactor(opts.identifierSource),
	}, nil
}

// NewNop returns a no-op logger that discards all events.
func NewNop() *Logger {
	return &Logger{
		zl:                 zerolog.Nop(),
		identifierRedactor: newLazyIdentifierRedactor(sharedIdentifierRedactor),
	}
}

func (l *Logger) subjectDiscriminator(subjectKey string) string {
	discriminator, err := l.identifierRedactor.discriminator(subjectKey)
	if err != nil {
		l.LogError(NewMethodLogContext("audit_identifier_redaction"), err)
		return ""
	}
	return discriminator
}

// SetEmitter sets the event emitter for external emission.
// Must be called before the logger is used concurrently (i.e., before
// the proxy starts serving). Not safe for concurrent use with Log methods.
func (l *Logger) SetEmitter(e *emit.Emitter) {
	l.emitter = e
}

// LogAllowed logs a successful, allowed request.
func (l *Logger) LogAllowed(ctx LogContext, statusCode, sizeBytes int, duration time.Duration) {
	if !l.includeAllowed {
		return
	}
	e := newLogEntry(l.zl.Info(), EventAllowed).
		str("method", ctx.method).
		optStr("url", ctx.url).
		optStr("target", ctx.target).
		optStr("resource", ctx.resource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		intField("status_code", statusCode).
		intField("size_bytes", sizeBytes).
		durMS(duration).
		agentField(ctx.agent, ctx.agentAuth)
	e.msg("request allowed")

	if l.emitter != nil {
		l.emitEvent(string(EventAllowed), e.fields)
	}
}

// BlockDetail carries the optional Result.Class and DNSErrorKind off the
// scanner package without forcing audit to depend on the scanner package.
// Empty values are tolerated: a zero BlockDetail behaves exactly like the
// existing LogBlocked call shape (ClassThreat, no DNS kind, MITRE technique
// drives off the scanner label as before).
//
// The only consumers today are the SSRF DNS resolution path (Class set to
// "infrastructure_error", DNSErrorKind set to one of timeout / no_such_host /
// resolver_error). Other Class values map onto display behavior the same way
// the canonical scanner package documents them: ClassProtective and
// ClassConfigMismatch suppress the MITRE technique because the block is not
// threat evidence, ClassThreat keeps it.
type BlockDetail struct {
	// Class mirrors scanner.Result.Class as a string. Empty defaults to
	// the threat class so the audit stream behaves exactly like the
	// pre-existing LogBlocked output.
	Class string
	// DNSErrorKind mirrors scanner.Result.DNSErrorKind on the SSRF DNS
	// resolution path. Empty when the block was not produced by a DNS
	// resolver failure. When set, it is also surfaced as a display label
	// so SIEMs can pivot on dns_timeout / dns_no_such_host /
	// dns_resolver_error directly.
	DNSErrorKind string
	// Header and Patterns identify a header DLP finding without logging its value.
	Header   string
	Patterns []string
	// Cookies names the Cookie pairs that carried a header DLP match. Names
	// only; a cookie value is never logged.
	Cookies []string
}

// Class string constants kept in lockstep with internal/scanner ResultClass.
// Audit stays string-typed to avoid an audit -> scanner import edge.
const (
	BlockClassThreat              = "threat"
	BlockClassProtective          = "protective"
	BlockClassConfigMismatch      = "config_mismatch"
	BlockClassInfrastructureError = "infrastructure_error"
	BlockClassStructuralExemption = "structural_exemption"
)

// LogBlocked logs a blocked request with the reason. Equivalent to
// LogBlockedDetail with a zero BlockDetail (threat class, no DNS kind).
func (l *Logger) LogBlocked(ctx LogContext, scanner, reason string) {
	l.LogBlockedDetail(ctx, scanner, reason, BlockDetail{})
}

// LogBlockedDetail is the class-aware variant of LogBlocked. When the block
// was classified as infrastructure_error on the SSRF DNS path, the audit
// stream drops the misleading mitre_technique tag (a resolver wobble is not
// MITRE T1046) and surfaces a dns_* display label so SIEM consumers can
// alert on resolver health distinctly from real SSRF probes. Scanner stays
// canonical ("ssrf") for suppression / metrics / receipts; only the
// presentation changes.
func (l *Logger) LogBlockedDetail(ctx LogContext, scanner, reason string, detail BlockDetail) {
	technique := TechniqueForScanner(scanner)
	displayLabel := ""
	// Suppress mitre_technique on non-threat classes. A protective block
	// (rate limit, data budget), a config-mismatch block (api_allowlist gap),
	// and an infrastructure-error block (DNS resolver wobble) are not
	// adversarial behavior, so attaching a MITRE ATT&CK technique to them
	// would poison SIEM dashboards that aggregate on the technique field.
	switch detail.Class {
	case BlockClassInfrastructureError:
		technique = ""
		// Surface the DNS subtype as the audit display label so a SIEM
		// query for dns_timeout vs dns_no_such_host vs dns_resolver_error
		// works without parsing the reason text.
		if detail.DNSErrorKind != "" {
			displayLabel = "dns_" + detail.DNSErrorKind
		}
	case BlockClassProtective, BlockClassConfigMismatch:
		technique = ""
	}

	// If the block came from a content-matching scanner, the URL/target
	// likely contains the very bytes that triggered the match. Emit the
	// scheme+host only so the credential is not echoed back into the
	// audit stream. See contentScanners for the eligible sources.
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventBlocked).
		str("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		str("scanner", scanner).
		str("reason", reason).
		optStr("header", detail.Header).
		agentField(ctx.agent, ctx.agentAuth).
		optStr("subject_discriminator", l.subjectDiscriminator(ctx.dowSubjectKey)).
		optStr("subject_trust", ctx.dowSubjectTrust).
		optStr("display_label", displayLabel).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scanner, reason)).
		optStr("mitre_technique", technique)
	if len(detail.Patterns) > 0 {
		e.strs("patterns", detail.Patterns)
	}
	if len(detail.Cookies) > 0 {
		e.strs("cookies", detail.Cookies)
	}

	// includeBlocked gates local audit log only - external emission always fires
	// so SIEM/webhook consumers see blocked events regardless of local verbosity.
	if l.includeBlocked {
		e.msg("request blocked")
	}
	if l.emitter != nil {
		l.emitEvent(string(EventBlocked), e.fields)
	}
}

// LogError logs a fetch error.
func (l *Logger) LogError(ctx LogContext, err error) {
	e := newLogEntry(l.zl.Error(), EventError).
		optStr("method", ctx.method).
		optStr("url", ctx.url).
		optStr("target", ctx.target).
		optStr("resource", ctx.resource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		errField(err)
	e.msg("request error")

	if l.emitter != nil {
		l.emitEvent(string(EventError), e.fields)
	}
}

// LogAnomaly logs suspicious but not blocked activity. The scanner parameter
// identifies which scanner/check produced the anomaly (e.g. "dlp", "ssrf").
// Pass an empty string for operational anomalies that aren't scanner-driven
// (startup warnings, readability failures, redirect hints).
func (l *Logger) LogAnomaly(ctx LogContext, scanner, reason string, score float64) {
	technique := TechniqueForScanner(scanner)

	// If the anomaly came from a content-matching scanner, the URL/target
	// likely contains the very bytes that triggered the match (a credential
	// in a query param, a seed phrase in a path). Redact to scheme+host so an
	// audit-mode warn does not echo the secret into operator sinks, matching
	// LogBlockedDetail. Non-content scanners keep the full URL.
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventAnomaly).
		str("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		optStr("subject_discriminator", l.subjectDiscriminator(ctx.dowSubjectKey)).
		optStr("subject_trust", ctx.dowSubjectTrust).
		optStr("scanner", scanner).
		optStr("mitre_technique", technique).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scanner, reason)).
		str("reason", reason).
		scoreField(score)
	e.msg("anomaly detected")

	if l.emitter != nil {
		l.emitEvent(string(EventAnomaly), e.fields)
	}
}

// LogContainmentMetricsDeny records a refused read of the containment-managed
// observability listener. Callers pass only the parsed peer IP and fixed
// endpoint path; request headers and metric contents are intentionally absent.
func (l *Logger) LogContainmentMetricsDeny(endpoint, sourceIP, configuredListener, reason string) {
	e := newLogEntry(l.zl.Warn(), EventContainmentMetricsDeny).
		str("endpoint", endpoint).
		str("client_ip", sourceIP).
		str("configured_listener", configuredListener).
		str("reason", reason).
		str("outcome", "denied")
	e.msg("containment metrics access denied")

	if l.emitter != nil {
		l.emitEventWithSeverity(emit.SeverityWarn, string(EventContainmentMetricsDeny), e.fields)
	}
}

// LogAgentIdentityCollision records a self-declared agent name that was
// neutralized because it collided with a reserved control actor.
func (l *Logger) LogAgentIdentityCollision(ctx LogContext, reservedAgent string) {
	const scanner = "agent_identity"
	technique := TechniqueForScanner(scanner)

	e := newLogEntry(l.zl.Warn(), EventAnomaly).
		str("method", ctx.method).
		optStr("url", ctx.url).
		optStr("target", ctx.target).
		optStr("resource", ctx.resource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		str("scanner", scanner).
		optStr("mitre_technique", technique).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditAgentIdentity, "reserved control actor")).
		str("reason", "self-declared agent neutralized: reserved control actor").
		str("reserved_agent", reservedAgent).
		scoreField(0.7)
	e.msg("agent identity collision")

	if l.emitter != nil {
		l.emitEvent(string(EventAnomaly), e.fields)
	}
}

// LogResponseScanExempt logs response_scanning.exempt_domains handling for the
// generic path, where scanning still runs but findings are pinned to warn. This
// is a dedicated event type (not "anomaly") so SIEM consumers can filter
// exemption events separately from actual security anomalies.
func (l *Logger) LogResponseScanExempt(ctx LogContext, hostname string) {
	l.logResponseScanExempt(ctx, hostname, "")
}

// LogResponseScanExemptFullTrust logs when response_scanning.exempt_domains
// causes a response body to stream without injection scanning.
func (l *Logger) LogResponseScanExemptFullTrust(ctx LogContext, hostname string) {
	l.logResponseScanExempt(ctx, hostname, responseScanExemptFullTrustEffect)
}

func (l *Logger) logResponseScanExempt(ctx LogContext, hostname, effect string) {
	// The basic (non-full-trust) exemption still SCANS the response for
	// visibility and pins any finding to warn with no adaptive scoring, so
	// saying "skipped" would overstate the exemption. "Skipped" is reserved for
	// the full-trust valve, where the body genuinely streams without scanning.
	msg := "response scan pinned to warn: exempt domain"
	reason := "exempt_domains match; findings pinned to warn (not scored)"
	if effect != "" {
		msg = "response scan skipped: exempt domain"
		reason = "exempt_domains match"
	}
	event := l.zl.Info().
		Str("event", string(EventResponseScanExempt)).
		Str("method", ctx.method)
	if ctx.url != "" {
		event = event.Str("url", sanitizeString(ctx.url))
	}
	if ctx.target != "" {
		event = event.Str("target", sanitizeString(ctx.target))
	}
	if ctx.resource != "" {
		event = event.Str("resource", sanitizeString(ctx.resource))
	}
	event = event.
		Str("hostname", hostname).
		Str("enforcement_type", "response_scanning").
		Str("reason", reason)
	if effect != "" {
		event = event.Str("effect", effect)
	}
	if ctx.clientIP != "" {
		event = event.Str("client_ip", ctx.clientIP)
	}
	if ctx.requestID != "" {
		event = event.Str("request_id", ctx.requestID)
	}
	if ctx.agent != "" {
		event = event.Str("agent", sanitizeString(ctx.agent)).Str("agent_auth", ctx.agentAuthOrUnknown())
	}
	event.Msg(msg)

	if l.emitter != nil {
		fields := map[string]any{
			"method":           ctx.method,
			"hostname":         hostname,
			"enforcement_type": "response_scanning",
			"reason":           reason,
		}
		if effect != "" {
			fields["effect"] = effect
		}
		if ctx.url != "" {
			fields["url"] = sanitizeString(ctx.url)
		}
		if ctx.target != "" {
			fields["target"] = sanitizeString(ctx.target)
		}
		if ctx.resource != "" {
			fields["resource"] = sanitizeString(ctx.resource)
		}
		if ctx.clientIP != "" {
			fields["client_ip"] = ctx.clientIP
		}
		if ctx.requestID != "" {
			fields["request_id"] = ctx.requestID
		}
		if !ctx.correlation.IsZero() {
			fields[FieldCorrelationID] = ctx.correlation.value
		}
		if ctx.agent != "" {
			fields["agent"] = sanitizeString(ctx.agent)
			fields["agent_auth"] = ctx.agentAuthOrUnknown()
		}
		l.emitEvent(string(EventResponseScanExempt), fields)
	}
}

// LogResponseScanExemptOverCapUnscanned logs when a response_scanning.exempt_domains
// host streams a body larger than the scan cap without injection scanning.
// This is observability only; enforcement remains controlled by the existing
// broad exemption behavior.
func (l *Logger) LogResponseScanExemptOverCapUnscanned(ctx LogContext, hostname, transport string, bytesWritten, scanCapBytes int64) {
	event := l.zl.Warn().
		Str("event", string(EventResponseScanExempt)).
		Str("method", ctx.method)
	if ctx.url != "" {
		event = event.Str("url", sanitizeString(ctx.url))
	}
	if ctx.target != "" {
		event = event.Str("target", sanitizeString(ctx.target))
	}
	if ctx.resource != "" {
		event = event.Str("resource", sanitizeString(ctx.resource))
	}
	event = event.
		Str("hostname", hostname).
		Str("transport", transport).
		Int64("bytes_written", bytesWritten).
		Int64("scan_cap_bytes", scanCapBytes).
		Str("enforcement_type", "response_scanning").
		Str("reason", "exempt_domains over-cap response streamed unscanned").
		Str("effect", responseScanExemptFullTrustEffect)
	if ctx.clientIP != "" {
		event = event.Str("client_ip", ctx.clientIP)
	}
	if ctx.requestID != "" {
		event = event.Str("request_id", ctx.requestID)
	}
	if ctx.agent != "" {
		event = event.Str("agent", sanitizeString(ctx.agent)).Str("agent_auth", ctx.agentAuthOrUnknown())
	}
	event.Msg("response scan exempt over-cap response streamed unscanned")

	if l.emitter != nil {
		fields := map[string]any{
			"method":           ctx.method,
			"hostname":         hostname,
			"transport":        transport,
			"bytes_written":    bytesWritten,
			"scan_cap_bytes":   scanCapBytes,
			"enforcement_type": "response_scanning",
			"reason":           "exempt_domains over-cap response streamed unscanned",
			"effect":           responseScanExemptFullTrustEffect,
		}
		if ctx.url != "" {
			fields["url"] = sanitizeString(ctx.url)
		}
		if ctx.target != "" {
			fields["target"] = sanitizeString(ctx.target)
		}
		if ctx.resource != "" {
			fields["resource"] = sanitizeString(ctx.resource)
		}
		if ctx.clientIP != "" {
			fields["client_ip"] = ctx.clientIP
		}
		if ctx.requestID != "" {
			fields["request_id"] = ctx.requestID
		}
		if !ctx.correlation.IsZero() {
			fields[FieldCorrelationID] = ctx.correlation.value
		}
		if ctx.agent != "" {
			fields["agent"] = sanitizeString(ctx.agent)
			fields["agent_auth"] = ctx.agentAuthOrUnknown()
		}
		l.emitEvent(string(EventResponseScanExempt), fields)
	}
}

// MediaExposureInfo carries the structured fields for a media_exposure
// event emitted by the audit logger. Populated by the proxy media policy
// helper (see internal/proxy/media_policy.go) and passed to
// LogMediaExposure so the audit layer and emit sinks see a dedicated
// media_exposure event type rather than a generic anomaly.
//
// Separate from internal/proxy.MediaExposureFields (which holds the
// pre-wiring payload) so the audit package doesn't import internal/proxy.
type MediaExposureInfo struct {
	Transport       string // "forward", "connect", "fetch", "reverse"
	ContentType     string
	Format          string // "jpeg", "png", "unknown"
	SizeBytes       int
	MetadataRemoved int
	BytesRemoved    int
	Blocked         bool
	BlockReason     string
}

// LogMediaExposure emits a dedicated media_exposure audit event with the
// structured fields taint/authority and SIEM consumers need to correlate
// media reaching an agent with downstream sensitive actions. Severity is
// SeverityWarn (set in internal/emit via EventSeverity map). Both the
// zerolog stream and the emitter sink receive the same field set.
//
// Unlike LogAnomaly this is not a suspicion marker - it is an exposure
// provenance signal. Every media response that reaches the agent (allowed
// or blocked) should produce one event when media_policy.log_media_exposure
// is enabled, so the downstream policy engine can build an exposure
// timeline.
func (l *Logger) LogMediaExposure(ctx LogContext, info MediaExposureInfo) {
	e := newLogEntry(l.zl.Warn(), EventMediaExposure).
		optStr("method", ctx.method).
		str("url", ctx.url).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		str("transport", info.Transport).
		str("content_type", info.ContentType).
		optStr("format", info.Format).
		intField("size_bytes", info.SizeBytes)
	if info.MetadataRemoved > 0 {
		e = e.intField("metadata_segments_removed", info.MetadataRemoved).
			intField("metadata_bytes_removed", info.BytesRemoved)
	}
	// Record block state as a structured field so SIEM consumers can
	// filter blocked vs allowed exposures without parsing the reason.
	e.event = e.event.Bool("blocked", info.Blocked)
	e.fields["blocked"] = info.Blocked
	if info.Blocked {
		e = e.optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditMediaPolicy, info.BlockReason))
		if info.BlockReason != "" {
			e = e.str("block_reason", info.BlockReason)
		}
	}
	if info.Blocked {
		e.msg("media response blocked by policy")
	} else {
		e.msg("media response reached agent")
	}

	if l.emitter != nil {
		l.emitEvent(string(EventMediaExposure), e.fields)
	}
}

// LogResponseScan logs a response content scan that found prompt injection patterns.
// When bundleRules is non-empty, bundle provenance is included in the audit event
// and webhook payload so SIEM consumers can identify which community rules matched.
func (l *Logger) LogResponseScan(ctx LogContext, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	const scanner = scannerpkg.AuditResponseScan
	technique := TechniqueForScanner(scanner)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventResponseScan).
		optStr("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		str("scanner", scanner).
		str("action", action).
		intField("match_count", matchCount).
		strs("patterns", patternNames).
		str("mitre_technique", technique).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditResponseScan, strings.Join(patternNames, ", "))).
		agentField(ctx.agent, ctx.agentAuth)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("response scan detected prompt injection")

	if l.emitter != nil {
		l.emitEvent(string(EventResponseScan), e.fields)
	}
}

// LogResponseScanSuppressed records a response-scanner finding deliberately
// left unenforced by destination-scoped policy.
func (l *Logger) LogResponseScanSuppressed(ctx LogContext, patternName, surface, reason string) {
	const scanner = scannerpkg.AuditResponseScan
	technique := TechniqueForScanner(scanner)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventResponseScanSuppressed).
		optStr("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		str("scanner", scanner).
		str("mode", "informational").
		str("pattern", patternName).
		str("surface", surface).
		str("reason", reason).
		str("mitre_technique", technique).
		agentField(ctx.agent, ctx.agentAuth)
	e.msg("response scan finding suppressed by policy")

	if l.emitter != nil {
		l.emitEvent(string(EventResponseScanSuppressed), e.fields)
	}
}

// CoreObserveAuthorization carries the declared exception that withheld a
// core-floor block, so the audit record names who accepted the risk and when
// the acceptance ends rather than only that something was observed.
type CoreObserveAuthorization struct {
	Host    string
	Reason  string
	Owner   string
	Expires string
}

// LogCoreResponseObserved records a core-floor finding that an operator's
// declared exception downgraded from block to observe.
//
// It reuses the response_scan_suppressed event so existing SIEM routing and
// severity mapping keep working, and separates itself by the core_observed
// classification plus the authorization fields. Ordinary suppression cannot
// reach the immutable floor at all, so those two cases must never look alike
// in an audit trail: an auditor reading this needs the pattern, the host it
// was allowed on, who authorized that, and the date it lapses.
func (l *Logger) LogCoreResponseObserved(ctx LogContext, patternName, surface string, auth CoreObserveAuthorization) {
	const scanner = scannerpkg.AuditResponseScan
	technique := TechniqueForScanner(scanner)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, scanner)

	e := newLogEntry(l.zl.Warn(), EventResponseScanSuppressed).
		optStr("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		str("scanner", scanner).
		str("mode", "informational").
		str("pattern", patternName).
		str("surface", surface).
		str("reason", "core_observed").
		optStr("observe_host", auth.Host).
		optStr("observe_owner", auth.Owner).
		optStr("observe_expires", auth.Expires).
		optStr("observe_reason", auth.Reason).
		str("mitre_technique", technique).
		agentField(ctx.agent, ctx.agentAuth)
	e.msg("core response finding observed under a declared operator exception")

	if l.emitter != nil {
		l.emitEvent(string(EventResponseScanSuppressed), e.fields)
	}
}

// TaintDecision bundles the per-event fields LogTaintDecision emits.
// The accompanying LogContext on the call carries request-level
// identifiers; TaintDecision carries the policy verdict and provenance.
type TaintDecision struct {
	TaintLevel  string
	ActionClass string
	Sensitivity string
	Authority   string
	Decision    string
	Reason      string
	SourceURL   string
	SourceKind  string
}

// LogTaintDecision logs a taint-aware policy evaluation for a sensitive action.
func (l *Logger) LogTaintDecision(ctx LogContext, d TaintDecision) {
	e := newLogEntry(l.zl.Warn(), EventTaintDecision).
		optStr("method", ctx.method).
		str("url", ctx.url).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		str("session_taint_level", d.TaintLevel).
		str("action_class", d.ActionClass).
		str("action_sensitivity", d.Sensitivity).
		str("authority_kind", d.Authority).
		str("decision", d.Decision).
		str("reason", d.Reason).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditTaintPolicy, d.Reason)).
		optStr("source_url", d.SourceURL).
		optStr("source_kind", d.SourceKind)
	e.msg("taint policy decision")

	if l.emitter != nil {
		l.emitEvent(string(EventTaintDecision), e.fields)
	}
}

// LogConfigReload logs a configuration reload event.
func (l *Logger) LogConfigReload(status, detail, configHash string) {
	e := newLogEntry(l.zl.Info(), EventConfigReload).
		str("status", status).
		str("detail", detail).
		str("config_hash", configHash)
	e.msg("configuration reloaded")

	if l.emitter != nil {
		l.emitEvent(string(EventConfigReload), e.fields)
	}
}

// RuleBundleDegradedEvent bundles the fields emitted for rule-bundle coverage
// degradation or rejection events.
type RuleBundleDegradedEvent struct {
	Bundle          string
	FailureClass    string
	Reason          string
	Phase           string
	Outcome         string
	Severity        string
	AllowDegraded   bool
	DroppedPatterns int
}

// LogRuleBundleDegraded logs a rule-bundle coverage degradation or rejection.
func (l *Logger) LogRuleBundleDegraded(ev RuleBundleDegradedEvent) {
	level := l.zl.Warn()
	emitSeverity := emit.SeverityWarn
	if ev.Severity == severityCritical || ev.Severity == "error" {
		level = l.zl.Error()
		emitSeverity = emit.SeverityCritical
	}
	e := newLogEntry(level, EventRuleBundleDegraded).
		str("bundle", ev.Bundle).
		str("failure_class", ev.FailureClass).
		str("reason", ev.Reason).
		str("phase", ev.Phase).
		str("outcome", ev.Outcome)
	e.event = e.event.Bool("allow_degraded", ev.AllowDegraded)
	e.fields["allow_degraded"] = ev.AllowDegraded
	if ev.DroppedPatterns > 0 {
		e.intField("dropped_patterns", ev.DroppedPatterns)
	}
	e.msg("rule bundle coverage degraded")

	if l.emitter != nil {
		l.emitEventWithSeverity(emitSeverity, string(EventRuleBundleDegraded), e.fields)
	}
}

// LicenseExpiryWarning is the operator-facing data for an active license
// expiry band.
type LicenseExpiryWarning struct {
	LicenseID     string
	Tier          string
	ThresholdDays int
	DaysRemaining int
	Severity      string
	ExpiresAt     string
	Message       string
}

// LogLicenseExpiry logs a renewal warning for the active enterprise license.
func (l *Logger) LogLicenseExpiry(warning LicenseExpiryWarning) {
	level := l.zl.Info()
	emitSeverity := emit.SeverityInfo
	switch warning.Severity {
	case severityCritical, "error":
		level = l.zl.Error()
		emitSeverity = emit.SeverityCritical
	case severityWarn:
		level = l.zl.Warn()
		emitSeverity = emit.SeverityWarn
	}
	e := newLogEntry(level, EventLicenseExpiry).
		str("license_id", warning.LicenseID).
		str("tier", warning.Tier).
		intField("threshold_days", warning.ThresholdDays).
		intField("days_remaining", warning.DaysRemaining).
		str("severity", warning.Severity).
		str("expires_at", warning.ExpiresAt).
		str("message", warning.Message)
	e.msg(warning.Message)

	if l.emitter != nil {
		l.emitEventWithSeverity(emitSeverity, string(EventLicenseExpiry), e.fields)
	}
}

// LogStartup logs that the proxy has started.
func (l *Logger) LogStartup(listenAddr, mode, version, configHash string) {
	e := newLogEntryRaw(l.zl.Info(), string(EventStartup)).
		str("listen", listenAddr).
		str("mode", mode).
		str("version", version).
		str("config_hash", configHash)
	e.msg("pipelock started")

	if l.emitter != nil {
		l.emitEvent(string(EventStartup), e.fields)
	}
}

// LogShutdown logs that the proxy is shutting down.
func (l *Logger) LogShutdown(reason string) {
	e := newLogEntryRaw(l.zl.Info(), string(EventShutdown)).
		str("reason", reason)
	e.msg("pipelock stopping")

	if l.emitter != nil {
		l.emitEvent(string(EventShutdown), e.fields)
	}
}

// LogAgentListener logs that a per-agent listener has started.
func (l *Logger) LogAgentListener(addr, agent string) {
	e := newLogEntry(l.zl.Info(), EventAgentListener).
		str("listen", addr).
		agentField(agent, string(envelope.ActorAuthUnknown))
	e.msg("agent listener started")

	if l.emitter != nil {
		l.emitEvent(string(EventAgentListener), e.fields)
	}
}

// copyRemediationHint copies remediation_hint from a log entry's fields into an
// external-emitter fields map when the entry set one, so the emitted event and
// the structured log carry the same operator guidance.
func copyRemediationHint(dst, src map[string]any) {
	if hint, ok := src["remediation_hint"]; ok {
		dst["remediation_hint"] = hint
	}
}

// LogMCPUnknownTool logs a tool call to a tool not in the session baseline.
func (l *Logger) LogMCPUnknownTool(toolName, action string) {
	technique := TechniqueForScanner("mcp_unknown_tool")

	e := newLogEntry(l.zl.Warn(), EventMCPUnknownTool).
		str("tool", toolName).
		str("action", action).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditMCPSessionBinding, "unknown tool")).
		str("mitre_technique", technique)
	e.msg("tool not in session baseline")

	if l.emitter != nil {
		l.emitEvent(string(EventMCPUnknownTool), e.fields)
	}
}

// LogSNIMismatch logs an SNI verification failure (domain fronting, malformed
// TLS, or timeout). Fields are structured per audit policy: connect_host and
// sni_host are explicit, never parsed from error text.
func (l *Logger) LogSNIMismatch(connectHost, sniHost, clientIP, requestID, agent, category string) {
	technique := TechniqueForScanner("sni_mismatch")

	e := newLogEntry(l.zl.Warn(), EventSNIMismatch).
		str("connect_host", connectHost).
		str("sni_host", sniHost).
		str("client_ip", clientIP).
		str("request_id", requestID).
		agentField(agent, string(envelope.ActorAuthUnknown)).
		str("category", category).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditSNIMismatch, category)).
		str("mitre_technique", technique)
	e.msg("SNI verification failed")

	if l.emitter != nil {
		l.emitEvent(string(EventSNIMismatch), e.fields)
	}
}

// LogKillSwitchDeny logs a request denied by the kill switch.
func (l *Logger) LogKillSwitchDeny(transport, endpoint, source, message, clientIP string) {
	e := newLogEntry(l.zl.Info(), EventKillSwitchDeny).
		str("transport", transport).
		str("endpoint", endpoint).
		str("source", source).
		str("deny_message", message).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditKillSwitch, source)).
		str("client_ip", clientIP)
	e.msg("kill switch denied request")

	if l.emitter != nil {
		l.emitEvent(string(EventKillSwitchDeny), e.fields)
	}
}

// LogBodyDLP logs a request body DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogBodyDLP(ctx LogContext, action string, matchCount int, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, string(EventBodyDLP))

	e := newLogEntry(l.zl.Warn(), EventBodyDLP).
		str("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		str("action", action).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		intField("match_count", matchCount).
		strs("patterns", patternNames).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.ScannerBodyDLP, "")).
		str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("request body DLP scan hit")

	if l.emitter != nil {
		l.emitEvent(string(EventBodyDLP), e.fields)
	}
}

// LogBodyScan logs a request body scan hit with a configurable event type.
// Used to distinguish address_protection from body_dlp in audit output.
func (l *Logger) LogBodyScan(ctx LogContext, eventType EventType, action string, matchCount int, findingNames []string) {
	technique := TechniqueForScanner(string(eventType))
	loggedURL, loggedTarget, loggedResource := redactedContentFields(ctx, string(eventType))
	e := newLogEntry(l.zl.Warn(), eventType).
		str("method", ctx.method).
		optStr("url", loggedURL).
		optStr("target", loggedTarget).
		optStr("resource", loggedResource).
		str("action", action).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		intField("match_count", matchCount).
		strs("findings", findingNames).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(string(eventType), strings.Join(findingNames, ", "))).
		optStr("mitre_technique", technique)
	e.msg("request body " + string(eventType) + " scan hit")

	if l.emitter != nil {
		l.emitEvent(string(eventType), e.fields)
	}
}

// LogHeaderDLP logs a request header DLP scan detection.
// When bundleRules is non-empty, bundle provenance is included in the audit event.
func (l *Logger) LogHeaderDLP(ctx LogContext, headerName, action string, patternNames []string, bundleRules []BundleRuleHit) {
	technique := TechniqueForScanner(ScannerDLP)

	e := newLogEntry(l.zl.Warn(), EventHeaderDLP).
		str("method", ctx.method).
		optStr("url", ctx.url).
		optStr("target", ctx.target).
		optStr("resource", ctx.resource).
		str("header", headerName).
		str("action", action).
		optStr("client_ip", ctx.clientIP).
		optStr("request_id", ctx.requestID).
		correlationField(ctx.correlation).
		agentField(ctx.agent, ctx.agentAuth).
		strs("patterns", patternNames).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditHeaderDLP, strings.Join(patternNames, ", "))).
		str("mitre_technique", technique)
	if len(bundleRules) > 0 {
		e.bundleRulesField(bundleRules)
	}
	e.msg("request header DLP scan hit")

	if l.emitter != nil {
		l.emitEvent(string(EventHeaderDLP), e.fields)
	}
}

// LogChainDetection logs a tool call chain pattern detection.
// LogChainDetection logs a tool call chain pattern match.
// Severity is derived from action (block=critical, warn=warn) per the
// architectural rule that event severity is hardcoded, not caller-controlled.
// The pattern's own severity is preserved as pattern_severity metadata.
func (l *Logger) LogChainDetection(pattern, patternSeverity, action, toolName, sessionKey string) {
	technique := TechniqueForChainPattern(pattern)

	// Derive severity from action, not from caller input.
	derivedSev := severityWarn
	if action == actionBlock {
		derivedSev = severityCritical
	}

	e := newLogEntry(l.zl.Warn(), EventChainDetection).
		str("pattern", pattern).
		str("pattern_severity", patternSeverity).
		str("severity", derivedSev).
		str("action", action).
		str("tool", toolName).
		str("session", sessionKey).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditChainDetection, pattern)).
		str("mitre_technique", technique)
	e.msg("chain pattern detected")

	if l.emitter != nil {
		sev := emit.SeverityWarn
		if action == actionBlock {
			sev = emit.SeverityCritical
		}
		l.emitEventWithSeverity(sev, string(EventChainDetection), e.fields)
	}
}

// LogSessionAdmin logs a session admin API operation (list, reset, auth failure).
func (l *Logger) LogSessionAdmin(action, clientIP, sessionKey, result string, statusCode int) {
	e := newLogEntry(l.zl.Info(), EventSessionAdmin).
		str("action", action).
		str("client_ip", clientIP).
		intField("status_code", statusCode).
		optStr("session_key", sessionKey).
		optStr("result", result)
	e.msg("session admin API")

	if l.emitter != nil {
		l.emitEvent(string(EventSessionAdmin), e.fields)
	}
}

// LogAirlockEnter logs that a session entered an airlock tier.
func (l *Logger) LogAirlockEnter(sessionKey, tier, trigger, clientIP, requestID string) {
	l.LogAirlockEnterForScope(sessionKey, "", tier, trigger, clientIP, requestID)
}

// LogAirlockEnterForScope identifies the destination of a scoped transition in
// both the local audit stream and the event sink. Empty scope is session-wide.
func (l *Logger) LogAirlockEnterForScope(sessionKey, scope, tier, trigger, clientIP, requestID string) {
	e := newLogEntry(l.zl.Warn(), EventAirlockEnter).
		str("session", sessionKey).
		optStr("scope", scope).
		str("tier", tier).
		str("trigger", trigger).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditAirlock, trigger)).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("session entered airlock")

	if l.emitter != nil {
		l.emitEvent(string(EventAirlockEnter), e.fields)
	}
}

// LogAirlockDeny logs a request denied by airlock enforcement.
func (l *Logger) LogAirlockDeny(sessionKey, tier, transport, method, clientIP, requestID string) {
	l.LogAirlockDenyReason(AirlockDenyOptions{
		SessionKey:      sessionKey,
		Tier:            tier,
		Transport:       transport,
		Method:          method,
		ClientIP:        clientIP,
		RequestID:       requestID,
		HTTPCorrelation: true,
	})
}

// AirlockDenyOptions describes an airlock denial audit event.
type AirlockDenyOptions struct {
	SessionKey      string
	Tier            string
	Transport       string
	Method          string
	Reason          string
	ClientIP        string
	RequestID       string
	HTTPCorrelation bool
}

// LogAirlockDenyReason logs an airlock denial with a transport-specific reason.
func (l *Logger) LogAirlockDenyReason(opts AirlockDenyOptions) {
	hintReason := opts.Reason
	if hintReason == "" {
		hintReason = opts.Tier
	}
	e := newLogEntry(l.zl.Warn(), EventAirlockDeny).
		str("session", opts.SessionKey).
		str("tier", opts.Tier).
		str("transport", opts.Transport).
		str("method", opts.Method).
		optStr("reason", hintReason).
		optStr("remediation_hint", scannerpkg.OperatorHintForResult(scannerpkg.AuditAirlock, hintReason))
	if opts.HTTPCorrelation {
		e = e.optStr("client_ip", opts.ClientIP).
			optStr("request_id", opts.RequestID)
	}
	e.msg("airlock denied request")

	if l.emitter != nil {
		l.emitEvent(string(EventAirlockDeny), e.fields)
	}
}

// LogAirlockDeescalate logs that a session's airlock tier was automatically reduced.
func (l *Logger) LogAirlockDeescalate(sessionKey, from, to, clientIP, requestID string) {
	e := newLogEntry(l.zl.Info(), EventAirlockDeescalate).
		str("session", sessionKey).
		str("from", from).
		str("to", to).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("airlock de-escalated")

	if l.emitter != nil {
		l.emitEvent(string(EventAirlockDeescalate), e.fields)
	}
}

// LogShieldRewrite logs that browser shield rewrote response content.
func (l *Logger) LogShieldRewrite(category string, hits int, transport, targetURL, clientIP, requestID string) {
	e := newLogEntry(l.zl.Info(), EventShieldRewrite).
		str("category", category).
		intField("hits", hits).
		str("transport", transport).
		str("url", targetURL).
		optStr("client_ip", clientIP).
		optStr("request_id", requestID)
	e.msg("browser shield rewrote content")

	if l.emitter != nil {
		l.emitEvent(string(EventShieldRewrite), e.fields)
	}
}

// With returns a sub-logger that includes the given key-value pair in every
// log entry. The sub-logger shares the parent's file handle and config but
// does NOT own the file - only the root logger should be Close()'d.
func (l *Logger) With(key, value string) *Logger {
	return &Logger{
		zl:                 l.zl.With().Str(key, value).Logger(),
		includeAllowed:     l.includeAllowed,
		includeBlocked:     l.includeBlocked,
		emitter:            l.emitter,
		identifierRedactor: l.identifierRedactor,
		correlation:        l.correlation,
	}
}

// Close cleans up the logger, flushing and closing any open file handles.
// Close is idempotent and safe to call multiple times.
func (l *Logger) Close() {
	if l.fileHandle != nil {
		_ = l.fileHandle.Sync()
		_ = l.fileHandle.Close()
		l.fileHandle = nil
	}
}
