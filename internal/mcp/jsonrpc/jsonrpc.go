// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package jsonrpc provides shared JSON-RPC 2.0 types used across the mcp
// sub-packages. Extracting these into a dedicated package breaks circular
// imports between tools/, policy/, and the parent mcp package.
package jsonrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Version is the JSON-RPC protocol version used by MCP.
const Version = "2.0"

// Null is the JSON literal "null", used to detect nil-equivalent
// json.RawMessage values that are non-nil Go slices.
const Null = "null"

// ContentBlock represents a single content block in an MCP tool result.
type ContentBlock struct {
	Type        string            `json:"type"`
	Text        string            `json:"text,omitempty"`
	Resource    *ResourceContents `json:"resource,omitempty"`
	Name        string            `json:"name,omitempty"`
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Data        string            `json:"data,omitempty"`
	Blob        string            `json:"blob,omitempty"`
	Raw         string            `json:"raw,omitempty"`
	MimeType    string            `json:"mimeType,omitempty"`
	MediaType   string            `json:"mediaType,omitempty"`
}

// ResourceContents is the content carried by an embedded MCP resource.
// Text is always agent-visible. Blob is scanned unless the VALUE is an
// encoded media payload; a field name alone does not make it opaque.
// Media policy handles declared MimeType separately.
type ResourceContents struct {
	URI      string `json:"uri,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ToolResult represents the result field of an MCP tool response.
type ToolResult struct {
	Content           []ContentBlock  `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
// Data is optional per JSON-RPC 2.0 but can carry arbitrary content,
// so it must be scanned for injection like any other text field.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RPCResponse represents a JSON-RPC 2.0 response envelope.
// Result is json.RawMessage (not *ToolResult) to handle non-standard result
// shapes without failing the entire parse - a typed *ToolResult would cause
// json.Unmarshal to error on string/array/non-object results, allowing bypass.
// Method and Params are included to scan server notifications for injection.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

const (
	// ScanScopeResponseInjection names the MCP response prompt-injection scanner.
	ScanScopeResponseInjection = "response_injection"
	// ScanScopeResponseDLP names the MCP response inbound text-DLP scanner.
	ScanScopeResponseDLP = "response_dlp"
)

// ScanVerdict describes the outcome of scanning a single MCP response for MCP
// response content. Clean means neither prompt-injection nor enforceable
// inbound DLP was found in the scanned response text; it does not mean tool
// policy or input scanning ran.
//
// Three states:
//   - Clean:     Clean=true, Scanned names the response scopes.
//   - Error:     Clean=false, Error set (parse/protocol failure). Not injection.
//   - Finding:   Clean=false, Error empty, Matches and/or DLPMatches and
//     Action set.
type ScanVerdict struct {
	Line  int             `json:"line"`
	ID    json.RawMessage `json:"id"`
	Clean bool            `json:"clean"`
	// Scanned is stamped by the surface that emits the verdict, not by each
	// ScanVerdict constructor. A new surface that marshals a verdict must set
	// it, otherwise the scope is silently absent from operator-facing output.
	Scanned []string                `json:"scanned,omitempty"`
	Action  string                  `json:"action,omitempty"`
	Matches []scanner.ResponseMatch `json:"matches,omitempty"`
	// DLPMatches contains enforceable inbound text-DLP findings. It is additive
	// to the long-standing injection Matches field so existing JSON consumers
	// retain their response-injection contract.
	DLPMatches []scanner.TextDLPMatch `json:"dlp_matches,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// ExtractStringsResult is the bounded recursive extraction result. Truncated is
// true when the JSON contains content beyond maxExtractDepth and a caller should
// fail closed rather than make a decision from partial strings.
type ExtractStringsResult struct {
	Strings   []string
	Truncated bool
}

// ExtractKeysResult is the bounded recursive JSON-key extraction result.
// Truncated is true when the JSON contains keys beyond maxExtractDepth.
type ExtractKeysResult struct {
	Keys      []string
	Truncated bool
}

// TextResult is the bounded text extraction result.
type TextResult struct {
	Text      string
	Truncated bool
}

// ExtractText extracts all text content from an MCP tool result.
// First tries to parse as a standard ToolResult with content blocks (extracting
// text from ALL block types, not just "text" - prevents bypass via image blocks).
// Falls back to recursively extracting all string values from arbitrary JSON,
// preventing bypass via non-standard result shapes.
//
// Content blocks are joined with a single space to preserve word boundaries.
// Between-word splits ("previous" + "instructions") produce intact injections
// the agent will act on - scanner must detect these. Mid-word splits
// ("Igno" + "re" → "Igno re") don't match, but the injection is also broken
// for the agent, so this is not exploitable.
func ExtractText(raw json.RawMessage) string {
	return ExtractTextResult(raw).Text
}

// ExtractTextResult extracts text content and reports uninspectable depth in
// the complete JSON value.
func ExtractTextResult(raw json.RawMessage) TextResult {
	if len(raw) == 0 || string(raw) == Null {
		return TextResult{}
	}
	if jsonDepthTruncated(raw) {
		return TextResult{Truncated: true}
	}

	// Try standard ToolResult structure first.
	var tr ToolResult
	if err := json.Unmarshal(raw, &tr); err == nil && (len(tr.Content) > 0 || tr.StructuredContent != nil) {
		var texts []string
		for _, block := range tr.Content {
			// Extract text from ALL content blocks, not just type=="text".
			// Non-text blocks (image, resource) may carry prompt injection
			// in their text field.
			if block.Text != "" {
				texts = append(texts, block.Text)
			}
			// Embedded resources carry their rendered text under resource.text,
			// rather than the top-level content block's text field. Treat it as
			// agent-visible response content while deliberately excluding opaque
			// resource blobs from prompt scanning.
			if block.Resource != nil && block.Resource.Text != "" {
				texts = append(texts, block.Resource.Text)
			}
			// resource_link metadata is also rendered to the agent. Keep URI
			// out of this text path; Name, Title, and Description are the
			// human-facing fields an attacker could use as instructions.
			for _, field := range []string{block.Name, block.Title, block.Description} {
				if field != "" {
					texts = append(texts, field)
				}
			}
			// Typed data/blob/raw fields are opaque only when the VALUE is
			// encoded media. A plaintext secret or instruction under
			// content[].data must be scanned, same as structuredContent.
			for _, field := range []string{block.Data, block.Blob, block.Raw} {
				texts = appendVisibleMediaField(texts, field)
			}
			if block.Resource != nil {
				texts = appendVisibleMediaField(texts, block.Resource.Blob)
			}
		}
		// structuredContent is rendered to the agent alongside content blocks.
		// Extract its text even when the typed content fast path succeeds, while
		// skipping only value-shaped opaque media.
		structured := ExtractVisibleStringsFromJSONResult(tr.StructuredContent)
		if structured.Truncated {
			return TextResult{Truncated: true}
		}
		texts = append(texts, structured.Strings...)
		// Always return after a successful ToolResult parse, even when
		// texts is empty. Falling through to ExtractStringsFromJSON would
		// feed base64 media in data/blob/raw fields into prompt scanning.
		return TextResult{Text: strings.Join(texts, " ")}
	}

	// Fallback: recursively extract all string values from arbitrary JSON.
	// Catches non-standard result shapes (plain string, nested objects, etc).
	extracted := ExtractStringsFromJSONResult(raw)
	if len(extracted.Strings) > 0 {
		return TextResult{Text: strings.Join(extracted.Strings, "\n"), Truncated: extracted.Truncated}
	}

	return TextResult{Truncated: extracted.Truncated}
}

// ExtractVisibleStringsFromJSONResult extracts agent-visible JSON string
// values while deliberately excluding opaque MCP media payloads. It is used
// for structuredContent, whose values are rendered to the agent but which may
// include image/resource payloads that must not be treated as prompt text.
//
// Opacity is decided by the VALUE, not by the key alone. A key such as data,
// blob or raw only nominates a string as a media candidate; the string is
// skipped when it is actually shaped like a media payload (base64 or a data
// URI). A nested object under such a key is walked normally, because
// structuredContent follows a tool-defined schema in which "data" is as often
// a record as a payload. Skipping by key name alone dropped every string
// inside {"data":{...}} and let a plaintext secret reach the client unscanned.
func ExtractVisibleStringsFromJSONResult(raw json.RawMessage) ExtractStringsResult {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ExtractStringsResult{}
	}

	var result []string
	truncated := false
	var extract func(interface{}, int, bool)
	extract = func(v interface{}, depth int, mediaCandidate bool) {
		if depth > maxExtractDepth {
			truncated = true
			return
		}
		switch val := v.(type) {
		case string:
			if mediaCandidate && isOpaqueMediaPayload(val) {
				return
			}
			result = append(result, val)
		case []interface{}:
			// An array under a media key is a list of payloads; each element
			// decides for itself by shape.
			for _, item := range val {
				extract(item, depth+1, mediaCandidate)
			}
		case map[string]interface{}:
			// Keys inside a nested object decide for themselves; a parent key
			// never makes a whole object opaque.
			for _, key := range SortedKeys(val) {
				extract(val[key], depth+1, isOpaqueMCPMediaField(key))
			}
		}
	}
	extract(parsed, 0, false)
	return ExtractStringsResult{Strings: result, Truncated: truncated}
}

// isOpaqueMCPMediaField reports whether a structuredContent key conventionally
// carries a media payload (MCP image and audio content use data, resource
// blobs use blob). The key alone only nominates the value; isOpaqueMediaPayload
// makes the decision.
func isOpaqueMCPMediaField(key string) bool {
	switch strings.ToLower(key) {
	case "blob", "data", "raw":
		return true
	default:
		return false
	}
}

// appendVisibleMediaField appends field when it is agent-visible text. Encoded
// media payloads stay out of prompt and inbound DLP scanning.
func appendVisibleMediaField(texts []string, field string) []string {
	if field != "" && !isOpaqueMediaPayload(field) {
		return append(texts, field)
	}
	return texts
}

// minOpaqueMediaPayloadLen is the shortest candidate considered at all. It only
// needs to cover the longest signature below, so it bounds work rather than
// standing in for a judgement about what media looks like.
const minOpaqueMediaPayloadLen = 16

// maxOpaqueMediaDecodeChars caps how much of a candidate payload is decoded to
// classify it. A container signature sits in the first bytes, so a prefix is
// enough and the work stays bounded on a large attachment. The value is a
// multiple of four so the prefix is a whole number of base64 quanta.
const maxOpaqueMediaDecodeChars = 64

// mediaSignatures are leading byte sequences published by binary container
// formats an MCP image, audio or resource-blob field can carry. PNG and JPEG
// are classified separately because a magic prefix alone is forgeable.
// Recognition is positive and deliberately incomplete: an unlisted format is
// treated as visible text and scanned, which costs scanning and never skips
// content. Only signatures specific enough that ordinary text cannot produce
// them are listed, so a two-byte printable prefix such as a bitmap's is
// deliberately absent.
var mediaSignatures = [][]byte{
	{'G', 'I', 'F', '8', '7', 'a'}, // GIF87a
	{'G', 'I', 'F', '8', '9', 'a'}, // GIF89a
	{'%', 'P', 'D', 'F', '-'},      // PDF
	{'O', 'g', 'g', 'S'},           // Ogg
	{'f', 'L', 'a', 'C'},           // FLAC
	{0x1a, 0x45, 0xdf, 0xa3},       // Matroska and WebM
}

var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

// pngIHDREnd is the offset after a canonical PNG signature and IHDR chunk
// (8 + 4 length + 4 type + 13 data + 4 CRC). Real PNGs put IHDR here; a
// magic prefix followed by text cannot.
const pngIHDREnd = 33

// minSmuggledTextRun is the shortest ASCII run after a media header that
// means the payload is text wrapped in a forged container, not media. It
// must fit in the bounded decode window after a PNG IHDR (48-33=15 bytes).
const minSmuggledTextRun = 12

// maxFtypBoxSize rejects an ISO-BMFF size field that cannot be a real ftyp
// box. Brands plus the 8-byte header fit in tens of bytes; 256 is well above
// any legitimate ftyp and still inside the decode prefix.
const maxFtypBoxSize = 256

// riffForms are the RIFF container forms carried as media. The four-character
// form name sits at byte offset 8, after "RIFF" and the chunk size.
var riffForms = [][]byte{
	[]byte("WEBP"),
	[]byte("WAVE"),
	[]byte("AVI "),
}

// isOpaqueMediaPayload reports whether a string value under a media key is an
// encoded BINARY media payload, which is the only thing the exclusion exists to
// keep out of prompt scanning.
//
// Two tests must both pass. The string is shaped like base64 (standard or URL
// alphabet, optional trailing padding, optional line wrapping), or a data URL
// that explicitly declares base64. Then its decoded leading bytes must carry a
// recognized media container signature. MCP specifies its typed image, audio
// and resource-blob fields as base64 strings, so a declared-base64 payload
// carrying a real container is the form the exclusion was written for.
//
// Failure direction: everything this rejects is scanned as text, so the cost of
// a wrong answer is extra scanning rather than skipped content. A
// base64-encoded credential carries no container signature and is therefore
// scanned. An unlisted or proprietary media format is also scanned, which can
// produce scanner work or a false positive on binary noise; that is the
// deliberate trade, because the opposite default is a silent bypass.
func isOpaqueMediaPayload(s string) bool {
	payload := s
	if strings.HasPrefix(s, "data:") {
		declared, ok := base64DataURLPayload(s)
		if !ok {
			// A data URL that does not declare base64, or is not a data URL at
			// all beyond its prefix, carries visible text.
			return false
		}
		payload = declared
	}
	if !isBase64MediaRun(payload) {
		return false
	}
	decoded, capped, ok := decodeMediaPrefix(payload)
	if !ok {
		return false
	}
	return hasMediaSignature(decoded, capped)
}

// hasMediaSignature reports whether decoded leading bytes are a recognized
// media container, not a magic prefix wrapping agent-visible text.
func hasMediaSignature(decoded []byte, capped bool) bool {
	// A truncated prefix cannot prove the unread tail is media. PNG/JPEG/GIF
	// headers plus non-printable padding filled the window and hid a
	// credential in the remaining base64. Fail closed and scan.
	if capped {
		return false
	}
	rest, ok := mediaPayloadAfterHeader(decoded)
	if !ok {
		return false
	}
	return !hasPrintableASCIIRun(rest, minSmuggledTextRun)
}

// mediaPayloadAfterHeader reports the bytes after a validated media header.
// Failure direction: a payload that does not prove its header is scanned.
func mediaPayloadAfterHeader(decoded []byte) ([]byte, bool) {
	if rest, ok := pngPayloadAfterIHDR(decoded); ok {
		return rest, true
	}
	if rest, ok := jpegPayloadAfterSOI(decoded); ok {
		return rest, true
	}
	for _, sig := range mediaSignatures {
		if bytes.HasPrefix(decoded, sig) {
			return decoded[len(sig):], true
		}
	}
	if bytes.HasPrefix(decoded, []byte("RIFF")) && len(decoded) >= 12 {
		for _, form := range riffForms {
			if bytes.Equal(decoded[8:12], form) {
				return decoded[12:], true
			}
		}
	}
	return ftypPayloadAfterBox(decoded)
}

func pngPayloadAfterIHDR(decoded []byte) ([]byte, bool) {
	if !bytes.HasPrefix(decoded, pngSignature) || len(decoded) < pngIHDREnd {
		return nil, false
	}
	if binary.BigEndian.Uint32(decoded[8:12]) != 13 || string(decoded[12:16]) != "IHDR" {
		return nil, false
	}
	return decoded[pngIHDREnd:], true
}

func jpegPayloadAfterSOI(decoded []byte) ([]byte, bool) {
	// JPEG SOI plus the start of the next marker (FF <type>). Type must be a
	// real segment code; ASCII such as 'I' from "Ignore..." is not.
	if len(decoded) < 4 || decoded[0] != 0xff || decoded[1] != 0xd8 || decoded[2] != 0xff {
		return nil, false
	}
	if decoded[3] < 0xc0 || decoded[3] > 0xfe {
		return nil, false
	}
	return decoded[4:], true
}

func ftypPayloadAfterBox(decoded []byte) ([]byte, bool) {
	// Same size floor as media.DetectType: a 32-bit box length must cover the
	// 8-byte header plus "ftyp" contents. Cap the size so a huge field cannot
	// hide trailing text inside a claimed box the prefix never contains.
	if len(decoded) < 8 || !bytes.Equal(decoded[4:8], []byte("ftyp")) {
		return nil, false
	}
	size := binary.BigEndian.Uint32(decoded[:4])
	if size < 12 || size > maxFtypBoxSize {
		return nil, false
	}
	if int(size) > len(decoded) {
		return nil, false
	}
	if int(size) == len(decoded) {
		return nil, true
	}
	return decoded[size:], true
}

func hasPrintableASCIIRun(b []byte, n int) bool {
	run := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			run++
			if run >= n {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// base64DataURLPayload returns the payload of a data URL that explicitly
// declares base64 encoding. RFC 2397 requires a comma between the metadata and
// the data, and the base64 form carries a `;base64` parameter last in the
// metadata. Anything else is not a base64 data URL.
func base64DataURLPayload(s string) (string, bool) {
	meta, data, found := strings.Cut(strings.TrimPrefix(s, "data:"), ",")
	if !found || !strings.HasSuffix(strings.ToLower(meta), ";base64") {
		return "", false
	}
	return data, true
}

// isBase64MediaRun reports whether s is long enough and drawn only from a
// base64 alphabet, allowing MIME line wrapping and at most two trailing
// padding characters.
func isBase64MediaRun(s string) bool {
	// A final MIME line ending sits after the padding, so remove it first.
	s = strings.TrimRight(s, "\r\n")
	if len(s) < minOpaqueMediaPayloadLen {
		return false
	}
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 {
		return false
	}
	chars := 0
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '-', c == '_':
			chars++
		case c == '\n', c == '\r':
			// Line-wrapped (MIME style) base64 is still one payload.
		default:
			return false
		}
	}
	return chars >= minOpaqueMediaPayloadLen
}

// decodeMediaPrefix decodes a bounded leading portion of a base64 candidate.
// It reports false when the candidate cannot be decoded, so an unreadable value
// is scanned as text instead of being skipped.
func decodeMediaPrefix(payload string) ([]byte, bool, bool) {
	compact, capped := compactBase64Prefix(payload)
	enc := base64.RawStdEncoding
	if strings.ContainsAny(compact, "-_") {
		enc = base64.RawURLEncoding
	}
	decoded, err := enc.DecodeString(compact)
	if err != nil || len(decoded) == 0 {
		return nil, false, false
	}
	return decoded, capped, true
}

// compactBase64Prefix copies at most maxOpaqueMediaDecodeChars payload bits,
// dropping MIME line wrapping as it goes, so a multi-megabyte attachment
// never allocates a second full copy just to classify its first bytes.
func compactBase64Prefix(payload string) (string, bool) {
	var b strings.Builder
	b.Grow(maxOpaqueMediaDecodeChars)
	i := 0
	for ; i < len(payload) && b.Len() < maxOpaqueMediaDecodeChars; i++ {
		c := payload[i]
		if c == '\r' || c == '\n' {
			continue
		}
		b.WriteByte(c)
	}
	compact := strings.TrimRight(b.String(), "=")
	capped := false
	for ; i < len(payload); i++ {
		c := payload[i]
		if c == '\r' || c == '\n' || c == '=' {
			continue
		}
		capped = true
		break
	}
	return compact, capped
}

// jsonDepthTruncated reports whether raw JSON exceeds the recursive extraction
// depth cap without returning any extracted strings.
func jsonDepthTruncated(raw json.RawMessage) bool {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	return valueDepthTruncated(parsed, 0)
}

// valueDepthTruncated walks arbitrary decoded JSON and stops when depth exceeds
// maxExtractDepth.
func valueDepthTruncated(v interface{}, depth int) bool {
	if depth > maxExtractDepth {
		return true
	}
	switch val := v.(type) {
	case []interface{}:
		for _, item := range val {
			if valueDepthTruncated(item, depth+1) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range val {
			if valueDepthTruncated(item, depth+1) {
				return true
			}
		}
	}
	return false
}

// SortedKeys returns the keys of a map in sorted order. Used by JSON extraction
// functions to ensure deterministic iteration - Go map order is random, so
// split-secret concat scanning would miss secrets nondeterministically without
// stable ordering.
func SortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// maxExtractDepth limits recursion in ExtractStringsFromJSON to prevent stack
// overflow from maliciously deeply-nested JSON.
const maxExtractDepth = 64

// maxExtractKeys bounds how many object keys one extraction contributes to the
// scanned text. Sized far above any real tool listing and far below what an
// adversarial one can produce: a server publishing a hundred tools with fifty
// parameters each stays well inside it, while a message engineered purely for
// breadth stops here and is reported truncated, which callers already treat as
// fail-closed. Chosen against a measurement rather than a guess: a 2.6MB
// listing carrying eighty thousand keys took roughly twenty seconds to scan
// before this bound existed.
const maxExtractKeys = 20000

// ExtractStringsForKeys extracts string values only from top-level keys
// matching the keyPattern regex. Values under non-matching keys are excluded.
// Nested values under matching keys are extracted recursively.
// Returns nil if keyPattern is nil (callers must provide a compiled pattern).
func ExtractStringsForKeys(raw json.RawMessage, keyPattern *regexp.Regexp) []string {
	return ExtractStringsForKeysResult(raw, keyPattern).Strings
}

// ExtractStringsForKeysResult extracts string values from matching top-level
// keys and reports whether recursive extraction hit the depth cap.
func ExtractStringsForKeysResult(raw json.RawMessage, keyPattern *regexp.Regexp) ExtractStringsResult {
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ExtractStringsResult{}
	}
	m, ok := parsed.(map[string]interface{})
	if !ok {
		return ExtractStringsResult{} // arguments must be an object
	}
	var result []string
	truncated := false
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
			truncated = true
			return
		}
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(val) {
				extract(val[k], depth+1)
			}
		}
	}
	if keyPattern == nil {
		return ExtractStringsResult{}
	}
	for _, k := range SortedKeys(m) {
		if keyPattern != nil && keyPattern.MatchString(k) {
			extract(m[k], 0)
		}
	}
	return ExtractStringsResult{Strings: result, Truncated: truncated}
}

// ExtractStringsFromJSON recursively extracts all string values from arbitrary JSON.
// Only extracts values (not keys) to avoid false positives from field names.
// Recursion is bounded by maxExtractDepth to prevent stack overflow.
func ExtractStringsFromJSON(raw json.RawMessage) []string {
	return ExtractStringsFromJSONResult(raw).Strings
}

// ExtractStringsFromJSONResult recursively extracts all string values from
// arbitrary JSON and reports whether extraction hit the nesting cap.
func ExtractStringsFromJSONResult(raw json.RawMessage) ExtractStringsResult {
	var result []string
	truncated := false
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		if depth > maxExtractDepth {
			truncated = true
			return
		}
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case []interface{}:
			for _, item := range val {
				extract(item, depth+1)
			}
		case map[string]interface{}:
			for _, k := range SortedKeys(val) {
				extract(val[k], depth+1)
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		extract(parsed, 0)
	}
	return ExtractStringsResult{Strings: result, Truncated: truncated}
}

// ExtractKeysFromJSONResult recursively extracts JSON object keys and reports
// whether extraction hit the nesting cap. Most response scanning deliberately
// ignores keys because they are normally structural. Callers that surface a
// JSON object as agent-visible tool metadata can opt into scanning its keys.
func ExtractKeysFromJSONResult(raw json.RawMessage) ExtractKeysResult {
	var result []string
	truncated := false
	var extract func(v interface{}, depth int)
	extract = func(v interface{}, depth int) {
		// Depth alone does not bound the work: a wide, shallow document stays
		// within maxExtractDepth while producing an unbounded number of keys,
		// and every key is then joined into text that each scanner pattern runs
		// over. Breadth is bounded here for the same reason depth is, and it
		// reports through the same Truncated flag, so a caller that already
		// fails closed on truncation needs no new branch.
		if depth > maxExtractDepth || len(result) >= maxExtractKeys {
			truncated = true
			return
		}
		switch val := v.(type) {
		case []interface{}:
			for _, item := range val {
				if len(result) >= maxExtractKeys {
					truncated = true
					return
				}
				extract(item, depth+1)
			}
		case map[string]interface{}:
			// Compare the object's size against the remaining budget BEFORE
			// sorting. SortedKeys allocates and sorts every key, which is the
			// expensive part, so checking afterwards paid the whole cost of a
			// hostile object and only then refused it.
			if len(val) > maxExtractKeys-len(result) {
				truncated = true
				return
			}
			for _, key := range SortedKeys(val) {
				if len(result) >= maxExtractKeys {
					truncated = true
					return
				}
				result = append(result, key)
				extract(val[key], depth+1)
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		extract(parsed, 0)
	}
	return ExtractKeysResult{Keys: result, Truncated: truncated}
}
