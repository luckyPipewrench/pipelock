// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/media"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const contentTypeOctetStream = "application/octet-stream"

const (
	svgMediaType                  = "image/svg+xml"
	svgIncompleteValidationReason = "media_policy: SVG requires complete browser-shield validation"
)

// isSVGContentType reports whether a response declares SVG, either by the
// parsed media type or by the browser-grammar essence Browser Shield uses when
// Go's MIME parser rejects later parameters.
func isSVGContentType(contentType string) bool {
	if canonicalContentType(contentType) == svgMediaType {
		return true
	}
	essence, ok := shieldMediaTypeEssence(contentType)
	return ok && essence == svgMediaType
}

// responseHeadersDeclareSVG reports whether the browser-visible MIME type of a
// response is SVG. A client renders "text/plain, image/svg+xml", or two
// separate Content-Type fields, as SVG even though the first value, which is
// all Header.Get returns, is inert.
func responseHeadersDeclareSVG(headers http.Header) bool {
	essence, ok := shieldMediaTypeEssence(responseMIMEType(headers))
	return ok && essence == svgMediaType
}

// responseMIMEType derives the MIME type a browser uses for a response from
// EVERY Content-Type field value, following the Fetch standard's "extract a
// MIME type": the values are combined and split on commas outside quoted
// strings; entries that do not parse and */* are skipped; the LAST valid entry
// wins. The charset of the winning entry is reset when its essence differs
// from the previously accepted one and carried forward when the essence is the
// same but the winner declares none. "text/plain;charset=gbk, text/html" is
// therefore text/html, while "text/html;charset=gbk, text/html" keeps the gbk
// charset.
//
// A single field value is returned as written so downstream classification of
// ordinary responses is unchanged. It returns "" when no value parses; callers
// that must keep the first-value behaviour for that case use
// responseContentType instead.
func responseMIMEType(headers http.Header) string {
	values := headers.Values("Content-Type")
	if len(values) == 0 {
		return ""
	}
	segments := splitHeaderValuesOutsideQuotes([]string{strings.Join(values, ", ")})
	last, lastEssence, charset := "", "", ""
	charsetPresent := false
	for _, segment := range segments {
		essence, ok := shieldMediaTypeEssence(segment)
		if !ok || essence == "*/*" {
			continue
		}
		own, hasCharset := responseMIMECharset(segment)
		if essence != lastEssence {
			charset = own
			charsetPresent = hasCharset
		}
		last, lastEssence = segment, essence
		if !hasCharset && charsetPresent {
			// Same essence, no charset of its own: the earlier one is kept.
			// Insert before malformed trailing parameters so a quoted value
			// cannot swallow the carried declaration.
			base, params, hasParams := strings.Cut(strings.TrimFunc(segment, isHTTPSpace), ";")
			encoded := charset
			if charset == "" {
				encoded = `""`
			}
			for i := 0; i < len(charset); i++ {
				if !shieldMIMETypeTokenByte(charset[i]) {
					encoded = "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(charset) + "\""
					break
				}
			}
			last = strings.TrimRight(base, " \t\r\n") + ";charset=" + encoded
			if hasParams {
				last += ";" + params
			}
		}
	}
	if last == "" {
		return ""
	}
	if len(segments) == 1 {
		return last
	}
	return strings.TrimFunc(last, isHTTPSpace)
}

// responseContentType is the browser-visible Content-Type for Browser Shield
// and media policy. Scan exemptions require responseMIMEEssencesAgree; taint
// observations use responseTaintContentType to retain every media declaration.
// When extraction fails it returns the first raw value to preserve the handling
// of empty or unparseable headers.
func responseContentType(headers http.Header) string {
	if derived := responseMIMEType(headers); derived != "" {
		return derived
	}
	return headers.Get("Content-Type")
}

func isHTTPSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

func splitHeaderValuesOutsideQuotes(values []string) []string {
	var segments []string
	for _, value := range values {
		start, quoted := 0, false
		for i := 0; i < len(value); i++ {
			switch value[i] {
			case '"':
				quoted = !quoted
			case '\\':
				if quoted {
					i++
				}
			case ',':
				if !quoted {
					segments = append(segments, value[start:i])
					start = i + 1
				}
			}
		}
		segments = append(segments, value[start:])
	}
	return segments
}

// svgValidationBlock refuses an SVG whose complete validation did not succeed.
func svgValidationBlock(reason string) *shieldBlockResult {
	return &shieldBlockResult{
		info:   blockInfoFor(blockreason.MediaPolicy, "media_policy"),
		status: http.StatusForbidden,
		reason: reason,
	}
}

const mediaPartialResponseBlockReason = "media policy cannot safely strip metadata from a partial response; request the complete resource or disable media_policy.strip_image_metadata for intentional passthrough"

// A stripped fragment no longer describes the upstream Content-Range, even if
// its length happens to match. Route through each transport's existing media
// block path so status, audit, receipts, and exposure agree on the refusal.
func refusePartialMediaRewrite(status int, verdict MediaPolicyVerdict) MediaPolicyVerdict {
	if status != http.StatusPartialContent || verdict.Blocked || verdict.StripResult == nil || !verdict.StripResult.Changed() {
		return verdict
	}
	verdict.Blocked = true
	verdict.BlockReason = mediaPartialResponseBlockReason
	verdict.Body = nil
	if verdict.Exposure != nil {
		exposure := *verdict.Exposure
		exposure.Blocked = true
		exposure.BlockReason = mediaPartialResponseBlockReason
		exposure.MetadataRemoved = 0
		exposure.BytesRemoved = 0
		verdict.Exposure = &exposure
	}
	return verdict
}

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

	// Relabeled is the image type the body's own header proves when the
	// upstream declared a different JPEG/PNG type (for example a WebP served
	// as image/png). Callers must forward it as the Content-Type so the
	// client and any later consumer are told what the bytes are. Empty
	// when the declared type was kept.
	Relabeled string

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

// mediaPolicyOptions carries facts established by an earlier response stage.
// SVG is active content, so its media admission is based on the complete
// Browser Shield validation pass, never a static MIME allowlist entry.
type mediaPolicyOptions struct {
	svgShielded bool
	// headers, when supplied, lets the SVG floor see every Content-Type value
	// the client will combine, not only the first one.
	headers http.Header
	// host is the response host. Image metadata is left intact for a shipped
	// bot-verification provider, whose challenge may read its images byte for
	// byte; every type, size and parse check still applies.
	host string
}

// isChallengeProviderHost reports whether host is a shipped bot-verification
// provider. Their challenge assets are consumed byte for byte by the
// challenge, so Pipelock does not rewrite them.
func isChallengeProviderHost(host string) bool {
	if host == "" {
		return false
	}
	for _, provider := range config.ShippedChallengeProviderHosts() {
		if scanner.MatchDomain(host, provider) {
			return true
		}
	}
	return false
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
func applyMediaPolicy(cfg *config.Config, contentType string, body []byte, options ...mediaPolicyOptions) MediaPolicyVerdict {
	option := mediaPolicyOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	mt := canonicalContentType(contentType)

	// SVG delivery floor. This is not an optional media-policy setting: a
	// response declared as SVG is delivered only when Browser Shield validated
	// the complete body. Disabled or exempt Shield, a partial or oversized
	// body, or a caller that never ran Shield all leave svgShielded false, so
	// the default for any caller that omits the option is refusal.
	declaredSVG := isSVGContentType(contentType) || responseHeadersDeclareSVG(option.headers)
	if declaredSVG && !option.svgShielded {
		return MediaPolicyVerdict{
			Blocked:     true,
			BlockReason: svgIncompleteValidationReason,
			MediaType:   svgMediaType,
		}
	}
	// A browser renders SVG when any Content-Type value it would use declares
	// it, while contentType is only the first value. Classify by what the
	// browser renders, so an earlier audio or video value cannot route a
	// validated SVG past the image policy.
	if declaredSVG {
		mt = svgMediaType
	}

	// Disabled policy: pure passthrough.
	if cfg == nil || !cfg.MediaPolicy.IsEnabled() {
		return MediaPolicyVerdict{Body: body, MediaType: mt}
	}

	if !declaredSVG {
		mt = effectiveMediaType(mt, body)
	}

	// Non-media content types pass through the media policy (content
	// scanning is handled by the response scanner elsewhere).
	if !isMediaType(mt) {
		return MediaPolicyVerdict{Body: body, MediaType: mt}
	}
	// Build the baseline exposure payload so all branches can share it.
	exposure := &MediaExposureFields{
		ContentType: audit.MediaContentType(mt),
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

	if mt != svgMediaType && !cfg.MediaPolicy.ImageTypeAllowed(mt) {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: image type %q not in allowed list", exposure.ContentType)
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

	// SVG admission is owned by the Browser Shield floor above, not by
	// AllowedImageTypes (config validation refuses SVG there). It still honors
	// the image block and size controls above; there is no binary metadata to
	// strip from an XML document.
	if mt == svgMediaType {
		return MediaPolicyVerdict{Body: body, MediaType: mt, Exposure: exposureOrNil(cfg, exposure)}
	}

	// A zero-byte body cannot carry metadata, so there is nothing to parse and
	// an absence must not be reported as malformed media. This sits AFTER the
	// audio and video decisions on purpose: the reverse proxy calls this with a
	// nil body precisely so those types can be refused without reading the
	// stream, and exempting empty bodies earlier let declared audio and video
	// through (TestReverseProxy_MediaPolicyBlocksAudio).
	if len(body) == 0 {
		return MediaPolicyVerdict{Body: body, MediaType: mt, Exposure: exposureOrNil(cfg, exposure)}
	}

	// Metadata surgery on allowed images.
	outBody := body
	var stripResult *media.StripResult
	relabeled := ""
	if sniffed, bad := media.MislabeledDisallowed(mt, body, cfg.MediaPolicy.ImageTypeAllowed); bad {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: declared image type %q does not match response bytes (bytes look like %s)", exposure.ContentType, sniffed)
		return MediaPolicyVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    exposureOrNil(cfg, exposure),
		}
	}
	if proven := media.StripType(mt, body, cfg.MediaPolicy.ImageTypeAllowed); proven != mt {
		relabeled = proven
		mt = proven
		exposure.ContentType = audit.MediaContentType(proven)
	}
	if cfg.MediaPolicy.ShouldStripImageMetadata() {
		sr, err := media.StripMetadata(mt, body)
		if err != nil {
			// Malformed image bytes. Fail closed: block rather than forward
			// potentially booby-trapped content. The error surfaces in the
			// exposure event for operator visibility.
			exposure.Blocked = true
			exposure.BlockReason = mediaParseBlockReason(mt, body, err)
			return MediaPolicyVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    exposureOrNil(cfg, exposure),
			}
		}
		// A bot-verification challenge may read its own images byte for byte,
		// so a challenge provider's image is parsed, and refused if malformed,
		// but forwarded exactly as received.
		if !isChallengeProviderHost(option.host) {
			stripResult = sr
			outBody = sr.Data
			exposure.Format = sr.Format
			exposure.MetadataRemoved = sr.SegmentsRemoved
			exposure.BytesRemoved = sr.BytesRemoved
		}
	}

	return MediaPolicyVerdict{
		Body:        outBody,
		MediaType:   mt,
		Relabeled:   relabeled,
		StripResult: stripResult,
		Exposure:    exposureOrNil(cfg, exposure),
	}
}

// applyRelabeledContentType forwards the proven image type when media policy
// reclassified a mislabeled body, so no downstream reader is told the bytes
// are the stripped format the upstream declared.
func applyRelabeledContentType(h http.Header, v MediaPolicyVerdict) {
	if v.Relabeled != "" && !v.Blocked && h != nil {
		h.Set("Content-Type", v.Relabeled)
	}
}

func mediaParseBlockReason(mediaType string, body []byte, err error) string {
	if errors.Is(err, media.ErrJPEGSignatureMismatch) || errors.Is(err, media.ErrPNGSignatureMismatch) {
		return fmt.Sprintf("media_policy: declared image type %q does not match response bytes (bytes look like %s)", mediaType, media.DescribeBytes(body))
	}
	return fmt.Sprintf("media_policy: image parse error: %v", err)
}

// effectiveMediaType treats a declared media type as authoritative only when
// it agrees with the bytes. DetectType validates the media header rather than
// trusting short prefixes such as "BM" or "ID3" on their own.
func effectiveMediaType(declared string, body []byte) string {
	if isMediaType(declared) || len(body) == 0 {
		return declared
	}
	if sniffed := sniffMediaType(body); sniffed != "" {
		return sniffed
	}
	return declared
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
	case "", contentTypeOctetStream, "binary/octet-stream", "application/binary", "application/unknown", "unknown/unknown", "*/*":
		return true
	}
	return false
}

// sniffMediaType uses the shared media-header parser so HTTP and MCP apply the
// same classification rule.
func sniffMediaType(body []byte) string {
	return media.DetectType(body)
}

// ToEventFields flattens the exposure payload into a map suitable for the
// emit.Event Fields map. Callers add transport/request/agent/source fields
// on top before dispatching the event.
func (m *MediaExposureFields) ToEventFields() map[string]any {
	f := map[string]any{
		"content_type": audit.MediaContentType(m.ContentType),
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
		ContentType:     audit.MediaContentType(m.ContentType),
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

// responseMIMEEssencesAgree permits scan relaxation only when every valid
// declaration names the same type. Invalid entries do not establish a type.
func responseMIMEEssencesAgree(headers http.Header) bool {
	last := ""
	for _, segment := range splitHeaderValuesOutsideQuotes(headers.Values("Content-Type")) {
		essence, ok := shieldMediaTypeEssence(segment)
		if !ok || essence == "*/*" {
			continue
		}
		if last != "" && last != essence {
			return false
		}
		last = essence
	}
	return last != ""
}

// responseTaintContentType preserves media exposure even when another client
// interprets a conflicting response as text. Source risk is independent of MIME.
func responseTaintContentType(headers http.Header) string {
	for _, segment := range splitHeaderValuesOutsideQuotes(headers.Values("Content-Type")) {
		if essence, ok := shieldMediaTypeEssence(segment); ok && isBinaryMIME(essence) {
			return essence
		}
	}
	return responseContentType(headers)
}

// responseMIMECharset reads MIME parameters using the browser grammar: quoted
// values consume embedded semicolons, malformed parameters are ignored, and
// the first valid charset wins. An empty quoted charset is still present.
func responseMIMECharset(value string) (string, bool) {
	_, rest, found := strings.Cut(value, ";")
	for found {
		rest = strings.TrimLeft(rest, " \t\r\n")
		end := strings.IndexAny(rest, ";=")
		if end < 0 {
			break
		}
		name := strings.ToLower(rest[:end])
		if rest[end] == ';' {
			rest = rest[end+1:]
			continue
		}
		rest = rest[end+1:]
		var parameter string
		if strings.HasPrefix(rest, "\"") {
			rest = rest[1:]
			var b strings.Builder
			for len(rest) > 0 {
				c := rest[0]
				rest = rest[1:]
				if c == '"' {
					break
				}
				if c == '\\' && len(rest) > 0 {
					c = rest[0]
					rest = rest[1:]
				}
				b.WriteByte(c)
			}
			parameter = b.String()
			_, rest, found = strings.Cut(rest, ";")
		} else {
			parameter, rest, found = strings.Cut(rest, ";")
			parameter = strings.TrimRight(parameter, " \t\r\n")
			if parameter == "" {
				continue
			}
		}
		valid := name != ""
		for i := 0; i < len(name); i++ {
			valid = valid && shieldMIMETypeTokenByte(name[i])
		}
		for i := 0; i < len(parameter); i++ {
			c := parameter[i]
			valid = valid && (c == '\t' || c >= 0x20 && c <= 0x7e || c >= 0x80)
		}
		if valid && name == "charset" {
			return parameter, true
		}
	}
	return "", false
}
