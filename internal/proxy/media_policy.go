// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/media"
)

// MediaPolicyVerdict is the decision a media policy evaluation produces for
// one response. Callers use it to route the body: blocked responses return
// 403 with BlockReason, stripped responses replace their body with Body,
// and unchanged responses (text/html, JSON, unknown) pass through with
// Body == the original bytes.
type MediaPolicyVerdict struct {
	// Body is the bytes to forward downstream. For blocked responses this
	// is nil. For stripped responses this is the metadata-free copy. For
	// passthrough responses this is the original buffer (not copied).
	Body []byte

	// Blocked is true when the media policy rejected the response entirely.
	// Callers must return HTTP 403 and NOT forward anything.
	Blocked bool

	// BlockReason is a short, operator-visible string explaining why a
	// response was blocked. Empty for non-blocked verdicts.
	BlockReason string

	// MediaType is the canonical lowercase Content-Type (no parameters).
	// Empty when Content-Type was missing or unparseable.
	MediaType string

	// StripResult is non-nil when image metadata surgery ran, regardless of
	// whether any metadata was actually removed. Lets callers log or
	// include strip counts in observability.
	StripResult *media.StripResult

	// Exposure is non-nil when the response crossed the agent boundary and
	// the policy wants an exposure event emitted. The caller populates the
	// source URL field before emission. Fields map fills as much as the
	// policy knows; the caller adds per-site context (transport, request
	// ID, agent).
	Exposure *MediaExposureFields
}

// MediaExposureFields carries the structured fields of a media_exposure
// event before the caller finalizes the source URL, transport, and
// request/agent identifiers. Kept as a plain struct (not an emit.Event)
// so the caller owns when and how the event is dispatched.
type MediaExposureFields struct {
	ContentType     string
	SizeBytes       int
	Format          string
	MetadataRemoved int
	BytesRemoved    int
	Blocked         bool
	BlockReason     string
}

// applyMediaPolicy evaluates a response body against cfg.MediaPolicy and
// returns a verdict describing what to forward and whether to emit an
// exposure event. Called from every transport that buffers a response body
// (TLS intercept, forward, fetch, reverse) so media policy enforcement is
// transport-agnostic.
//
// The function is deliberately allocation-light: for passthrough (non-media
// or disabled policy), it returns the input slice unmodified with no
// StripResult or Exposure. Non-nil Exposure signals to the caller that a
// media_exposure event should be emitted.
func applyMediaPolicy(cfg *config.Config, contentType string, body []byte) MediaPolicyVerdict {
	mt := canonicalContentType(contentType)

	// Disabled policy: pure passthrough.
	if cfg == nil || !cfg.MediaPolicy.IsEnabled() {
		return MediaPolicyVerdict{Body: body, MediaType: mt}
	}

	// Content sniffing closes the header-spoofing bypass: an attacker who
	// relabels a JPEG as application/octet-stream (or strips Content-Type
	// entirely) would otherwise skip the isMediaType gate below and
	// escape every media-policy check. When the declared type is missing
	// or generic, sniff the first 512 bytes and use the detected type if
	// it falls under the policy's scope.
	//
	// We do NOT override explicit non-generic declarations like text/html
	// or application/pdf — those are deliberate content-type claims that
	// the upstream may well honor. The attacker path this closes is the
	// common case of a raw byte dump with no or default Content-Type.
	if !isMediaType(mt) && contentTypeIsGeneric(mt) && len(body) > 0 {
		if sniffed := sniffMediaType(body); sniffed != "" {
			mt = sniffed
		}
	}

	// Non-media content types pass through the media policy (content
	// scanning is handled by the response scanner elsewhere).
	if !isMediaType(mt) {
		return MediaPolicyVerdict{Body: body, MediaType: mt}
	}

	// Build the baseline exposure payload so all branches can share it.
	exposure := &MediaExposureFields{
		ContentType: mt,
		SizeBytes:   len(body),
	}

	// Audio / video: reject when stripped (the default) regardless of size.
	if strings.HasPrefix(mt, "audio/") {
		if cfg.MediaPolicy.ShouldStripAudio() {
			exposure.Blocked = true
			exposure.BlockReason = "media_policy: audio stripped"
			return MediaPolicyVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    exposureOrNil(cfg, exposure),
			}
		}
		return MediaPolicyVerdict{Body: body, MediaType: mt, Exposure: exposureOrNil(cfg, exposure)}
	}
	if strings.HasPrefix(mt, "video/") {
		if cfg.MediaPolicy.ShouldStripVideo() {
			exposure.Blocked = true
			exposure.BlockReason = "media_policy: video stripped"
			return MediaPolicyVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    exposureOrNil(cfg, exposure),
			}
		}
		return MediaPolicyVerdict{Body: body, MediaType: mt, Exposure: exposureOrNil(cfg, exposure)}
	}

	// Image branch.
	if !strings.HasPrefix(mt, "image/") {
		// Shouldn't happen (isMediaType only accepts image/audio/video)
		// but return passthrough defensively instead of panicking.
		return MediaPolicyVerdict{Body: body, MediaType: mt}
	}

	if cfg.MediaPolicy.ShouldStripImages() {
		exposure.Blocked = true
		exposure.BlockReason = "media_policy: images stripped"
		return MediaPolicyVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    exposureOrNil(cfg, exposure),
		}
	}

	if !cfg.MediaPolicy.ImageTypeAllowed(mt) {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: image type %q not in allowed list", mt)
		return MediaPolicyVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    exposureOrNil(cfg, exposure),
		}
	}

	if int64(len(body)) > cfg.MediaPolicy.EffectiveMaxImageBytes() {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: image size %d exceeds limit %d",
			len(body), cfg.MediaPolicy.EffectiveMaxImageBytes())
		return MediaPolicyVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    exposureOrNil(cfg, exposure),
		}
	}

	// Metadata surgery on allowed images.
	outBody := body
	var stripResult *media.StripResult
	if cfg.MediaPolicy.ShouldStripImageMetadata() {
		sr, err := media.StripMetadata(mt, body)
		if err != nil {
			// Malformed image bytes. Fail closed: block rather than forward
			// potentially booby-trapped content. The error surfaces in the
			// exposure event for operator visibility.
			exposure.Blocked = true
			exposure.BlockReason = fmt.Sprintf("media_policy: image parse error: %v", err)
			return MediaPolicyVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    exposureOrNil(cfg, exposure),
			}
		}
		stripResult = sr
		outBody = sr.Data
		exposure.Format = sr.Format
		exposure.MetadataRemoved = sr.SegmentsRemoved
		exposure.BytesRemoved = sr.BytesRemoved
	}

	return MediaPolicyVerdict{
		Body:        outBody,
		MediaType:   mt,
		StripResult: stripResult,
		Exposure:    exposureOrNil(cfg, exposure),
	}
}

// exposureOrNil returns the exposure payload when event emission is enabled
// for the policy, otherwise nil. Keeps the branch logic at the top of
// applyMediaPolicy concise.
func exposureOrNil(cfg *config.Config, fields *MediaExposureFields) *MediaExposureFields {
	if cfg == nil || !cfg.MediaPolicy.ShouldLogExposure() {
		return nil
	}
	return fields
}

// canonicalContentType parses a Content-Type header and returns the
// lowercase media type with parameters stripped. Returns "" on parse error
// or empty input.
func canonicalContentType(contentType string) string {
	if contentType == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
			return strings.ToLower(strings.TrimSpace(contentType[:idx]))
		}
		return strings.ToLower(strings.TrimSpace(contentType))
	}
	return strings.ToLower(mt)
}

// isMediaType reports whether a canonical media type string falls under
// the media policy's scope (image, audio, or video). Any other prefix
// (text, application, multipart, etc.) passes through untouched.
func isMediaType(mt string) bool {
	return strings.HasPrefix(mt, "image/") ||
		strings.HasPrefix(mt, "audio/") ||
		strings.HasPrefix(mt, "video/")
}

// contentTypeIsGeneric reports whether a Content-Type value is effectively
// unspecified and therefore a candidate for content sniffing. An explicit
// declaration like text/html or application/pdf is respected; a missing or
// application/octet-stream declaration means "unknown bytes" and the
// sniffer is allowed to override.
func contentTypeIsGeneric(mt string) bool {
	switch mt {
	case "", "application/octet-stream", "binary/octet-stream", "application/binary", "application/unknown":
		return true
	}
	return false
}

// sniffMediaType runs net/http.DetectContentType on the first 512 bytes of
// body and returns the canonical media type if the result falls under the
// media policy's scope (image, audio, or video). Returns "" otherwise.
// Isolated here so callers can add their own sniffing heuristics later
// without touching applyMediaPolicy.
func sniffMediaType(body []byte) string {
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	sniffed := canonicalContentType(httpDetectContentType(head))
	if isMediaType(sniffed) {
		return sniffed
	}
	return ""
}

// httpDetectContentType is a seam for testing. Aliased to net/http's
// DetectContentType; tests can shadow this package-level variable in the
// future to inject specific sniffs without constructing crafted bodies.
var httpDetectContentType = http.DetectContentType

// ToEventFields flattens the exposure payload into a map suitable for the
// emit.Event Fields map. Callers add transport/request/agent/source fields
// on top before dispatching the event.
func (m *MediaExposureFields) ToEventFields() map[string]any {
	f := map[string]any{
		"content_type": m.ContentType,
		"size_bytes":   m.SizeBytes,
		"blocked":      m.Blocked,
	}
	if m.Format != "" {
		f["format"] = m.Format
	}
	if m.MetadataRemoved > 0 {
		f["metadata_segments_removed"] = m.MetadataRemoved
		f["metadata_bytes_removed"] = m.BytesRemoved
	}
	if m.BlockReason != "" {
		f["block_reason"] = m.BlockReason
	}
	return f
}

// ToAuditInfo projects the proxy-side exposure payload into the audit
// package's MediaExposureInfo shape so the caller can dispatch via
// Logger.LogMediaExposure. Transport is a per-site constant ("forward",
// "connect", "fetch", "reverse") that the caller knows and the policy
// helper does not.
func (m *MediaExposureFields) ToAuditInfo(transport string) audit.MediaExposureInfo {
	return audit.MediaExposureInfo{
		Transport:       transport,
		ContentType:     m.ContentType,
		Format:          m.Format,
		SizeBytes:       m.SizeBytes,
		MetadataRemoved: m.MetadataRemoved,
		BytesRemoved:    m.BytesRemoved,
		Blocked:         m.Blocked,
		BlockReason:     m.BlockReason,
	}
}

// mediaPolicyLogger captures the audit hooks a transport needs to emit
// media_exposure events. Kept as an interface so tests and sites can pass
// any object satisfying the shape (the real *audit.Logger does).
type mediaPolicyLogger interface {
	LogMediaExposure(ctx audit.LogContext, info audit.MediaExposureInfo)
}

// logMediaExposureIfPresent emits a media_exposure event when the verdict
// carries an exposure payload. Centralizes the per-site logging so all
// transport wires look identical and SIEM output stays consistent across
// forward / connect / fetch / reverse.
func logMediaExposureIfPresent(logger mediaPolicyLogger, ctx audit.LogContext, verdict MediaPolicyVerdict, transport string) {
	if verdict.Exposure == nil || logger == nil {
		return
	}
	logger.LogMediaExposure(ctx, verdict.Exposure.ToAuditInfo(transport))
}
