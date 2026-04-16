// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/media"
)

type mcpMediaPolicyResult struct {
	Line        []byte
	Changed     bool
	Blocked     bool
	BlockReason string
	Exposures   []audit.MediaExposureInfo
}

type mcpMediaVerdict struct {
	Body        []byte
	MediaType   string
	Blocked     bool
	BlockReason string
	StripResult *media.StripResult
	Exposure    *audit.MediaExposureInfo
}

func applyMCPResponseMediaPolicy(line []byte, policy *config.MediaPolicy, transport string) mcpMediaPolicyResult {
	result := mcpMediaPolicyResult{Line: line}
	if policy == nil || !policy.IsEnabled() {
		return result
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(line, &rpc); err != nil {
		return result
	}

	rawResult, ok := rpc["result"]
	if !ok || len(rawResult) == 0 || string(rawResult) == jsonrpc.Null {
		return result
	}

	rewritten, changed, blockReason, exposures := rewriteMCPToolResultMedia(rawResult, policy, transport)
	result.Exposures = exposures
	if blockReason != "" {
		result.Blocked = true
		result.BlockReason = blockReason
		return result
	}
	if !changed {
		return result
	}

	rpc["result"] = rewritten
	updated, err := json.Marshal(rpc)
	if err != nil {
		result.Blocked = true
		result.BlockReason = fmt.Sprintf("media_policy: re-marshal MCP response: %v", err)
		return result
	}
	result.Line = updated
	result.Changed = true
	return result
}

func rewriteMCPToolResultMedia(raw json.RawMessage, policy *config.MediaPolicy, transport string) (json.RawMessage, bool, string, []audit.MediaExposureInfo) {
	var resultMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resultMap); err != nil {
		return raw, false, "", nil
	}

	contentRaw, ok := resultMap["content"]
	if !ok || len(contentRaw) == 0 || string(contentRaw) == jsonrpc.Null {
		return raw, false, "", nil
	}

	var content []jsonrpc.ContentBlock
	if err := json.Unmarshal(contentRaw, &content); err != nil || len(content) == 0 {
		return raw, false, "", nil
	}

	changed := false
	exposures := make([]audit.MediaExposureInfo, 0, len(content))

	for i := range content {
		fields := mcpMediaPayloadFields(content[i])
		if len(fields) == 0 {
			continue
		}

		contentType, hinted := mcpMediaHint(content[i])

		for _, field := range fields {
			decoded, ok := decodeMCPMediaPayload(field.encoded)
			if !ok {
				if field.looksLikeMedia {
					return raw, changed, fmt.Sprintf("media_policy: invalid base64 in result.content[%d].%s", i, field.name), exposures
				}
				continue
			}

			verdict := applyMCPMediaPolicy(policy, contentType, decoded, transport)
			if verdict.Exposure != nil {
				exposures = append(exposures, *verdict.Exposure)
			}
			if hinted && verdict.MediaType == "" {
				return raw, changed, fmt.Sprintf("media_policy: unsupported media in result.content[%d].%s", i, field.name), exposures
			}
			if verdict.Blocked {
				return raw, changed, verdict.BlockReason, exposures
			}
			if verdict.StripResult != nil && verdict.StripResult.Changed() {
				encodedOut := base64.StdEncoding.EncodeToString(verdict.Body)
				switch field.name {
				case "data":
					content[i].Data = encodedOut
				case "blob":
					content[i].Blob = encodedOut
				case "raw":
					content[i].Raw = encodedOut
				}
				changed = true
			}
		}
	}

	if !changed {
		return raw, false, "", exposures
	}

	updatedContent, err := json.Marshal(content)
	if err != nil {
		return raw, false, fmt.Sprintf("media_policy: re-marshal tool result content: %v", err), exposures
	}
	resultMap["content"] = updatedContent

	updated, err := json.Marshal(resultMap)
	if err != nil {
		return raw, false, fmt.Sprintf("media_policy: re-marshal tool result: %v", err), exposures
	}
	return updated, true, "", exposures
}

// mcpMediaField represents a single payload field within a content block.
type mcpMediaField struct {
	name           string
	encoded        string
	looksLikeMedia bool
}

// mcpMediaPayloadFields returns ALL non-empty payload fields (data, blob, raw)
// for a content block. The MCP spec allows only ONE payload field per block, but
// fail-closed means we scan all populated fields to prevent a bypass where
// blocked media hides in blob while benign content sits in data.
func mcpMediaPayloadFields(block jsonrpc.ContentBlock) []mcpMediaField {
	looksMedia := mcpContentBlockLooksLikeMedia(block)
	var fields []mcpMediaField
	if block.Data != "" {
		fields = append(fields, mcpMediaField{"data", block.Data, looksMedia})
	}
	if block.Blob != "" {
		fields = append(fields, mcpMediaField{"blob", block.Blob, looksMedia})
	}
	if block.Raw != "" {
		fields = append(fields, mcpMediaField{"raw", block.Raw, looksMedia})
	}
	return fields
}

func mcpContentBlockLooksLikeMedia(block jsonrpc.ContentBlock) bool {
	if mt, ok := mcpMediaHint(block); ok && mt != "" {
		return true
	}
	switch strings.ToLower(block.Type) {
	case "image", "audio", "video":
		return true
	default:
		return false
	}
}

func mcpMediaHint(block jsonrpc.ContentBlock) (string, bool) {
	if mt := canonicalMCPContentType(block.MimeType); isMCPMediaType(mt) {
		return mt, true
	}
	if mt := canonicalMCPContentType(block.MediaType); isMCPMediaType(mt) {
		return mt, true
	}
	switch strings.ToLower(block.Type) {
	case "audio":
		return "audio/unknown", true
	case "video":
		return "video/unknown", true
	case "image":
		return "", true
	default:
		return "", false
	}
}

func decodeMCPMediaPayload(encoded string) ([]byte, bool) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(trimmed)
		if err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

func applyMCPMediaPolicy(policy *config.MediaPolicy, contentType string, body []byte, transport string) mcpMediaVerdict {
	mt := canonicalMCPContentType(contentType)
	if policy == nil || !policy.IsEnabled() {
		return mcpMediaVerdict{Body: body, MediaType: mt}
	}

	if !isMCPMediaType(mt) && mcpContentTypeIsGeneric(mt) && len(body) > 0 {
		if sniffed := sniffMCPMediaType(body); sniffed != "" {
			mt = sniffed
		}
	}

	if !isMCPMediaType(mt) {
		return mcpMediaVerdict{Body: body, MediaType: mt}
	}

	exposure := &audit.MediaExposureInfo{
		Transport:   transport,
		ContentType: mt,
		SizeBytes:   len(body),
	}

	if strings.HasPrefix(mt, "audio/") {
		if policy.ShouldStripAudio() {
			exposure.Blocked = true
			exposure.BlockReason = "media_policy: audio stripped"
			return mcpMediaVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    mcpExposureOrNil(policy, exposure),
			}
		}
		return mcpMediaVerdict{Body: body, MediaType: mt, Exposure: mcpExposureOrNil(policy, exposure)}
	}
	if strings.HasPrefix(mt, "video/") {
		if policy.ShouldStripVideo() {
			exposure.Blocked = true
			exposure.BlockReason = "media_policy: video stripped"
			return mcpMediaVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    mcpExposureOrNil(policy, exposure),
			}
		}
		return mcpMediaVerdict{Body: body, MediaType: mt, Exposure: mcpExposureOrNil(policy, exposure)}
	}

	if !strings.HasPrefix(mt, "image/") {
		return mcpMediaVerdict{Body: body, MediaType: mt}
	}
	if policy.ShouldStripImages() {
		exposure.Blocked = true
		exposure.BlockReason = "media_policy: images stripped"
		return mcpMediaVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    mcpExposureOrNil(policy, exposure),
		}
	}
	if !policy.ImageTypeAllowed(mt) {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: image type %q not in allowed list", mt)
		return mcpMediaVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    mcpExposureOrNil(policy, exposure),
		}
	}
	if int64(len(body)) > policy.EffectiveMaxImageBytes() {
		exposure.Blocked = true
		exposure.BlockReason = fmt.Sprintf("media_policy: image size %d exceeds limit %d", len(body), policy.EffectiveMaxImageBytes())
		return mcpMediaVerdict{
			Blocked:     true,
			BlockReason: exposure.BlockReason,
			MediaType:   mt,
			Exposure:    mcpExposureOrNil(policy, exposure),
		}
	}

	outBody := body
	var stripResult *media.StripResult
	if policy.ShouldStripImageMetadata() {
		sr, err := media.StripMetadata(mt, body)
		if err != nil {
			exposure.Blocked = true
			exposure.BlockReason = fmt.Sprintf("media_policy: image parse error: %v", err)
			return mcpMediaVerdict{
				Blocked:     true,
				BlockReason: exposure.BlockReason,
				MediaType:   mt,
				Exposure:    mcpExposureOrNil(policy, exposure),
			}
		}
		stripResult = sr
		outBody = sr.Data
		exposure.Format = sr.Format
		exposure.MetadataRemoved = sr.SegmentsRemoved
		exposure.BytesRemoved = sr.BytesRemoved
	}

	return mcpMediaVerdict{
		Body:        outBody,
		MediaType:   mt,
		StripResult: stripResult,
		Exposure:    mcpExposureOrNil(policy, exposure),
	}
}

func mcpExposureOrNil(policy *config.MediaPolicy, info *audit.MediaExposureInfo) *audit.MediaExposureInfo {
	if policy == nil || !policy.ShouldLogExposure() {
		return nil
	}
	return info
}

func canonicalMCPContentType(contentType string) string {
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

func isMCPMediaType(mt string) bool {
	return strings.HasPrefix(mt, "image/") || strings.HasPrefix(mt, "audio/") || strings.HasPrefix(mt, "video/")
}

func mcpContentTypeIsGeneric(mt string) bool {
	return mt == "" || mt == "application/octet-stream" || mt == "binary/octet-stream"
}

func sniffMCPMediaType(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	sniffed := canonicalMCPContentType(http.DetectContentType(head))
	if isMCPMediaType(sniffed) {
		return sniffed
	}
	return ""
}
