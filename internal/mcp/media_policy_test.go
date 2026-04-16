// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testMCPMediaTransport = "mcp_stdio"
)

func TestMCPMediaHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		block      jsonrpc.ContentBlock
		wantType   string
		wantHinted bool
	}{
		{
			name:       "mimeType_image_jpeg",
			block:      jsonrpc.ContentBlock{MimeType: "image/jpeg"},
			wantType:   "image/jpeg",
			wantHinted: true,
		},
		{
			name:       "mediaType_image_png",
			block:      jsonrpc.ContentBlock{MediaType: "image/png"},
			wantType:   "image/png",
			wantHinted: true,
		},
		{
			name:       "mimeType_takes_precedence_over_mediaType",
			block:      jsonrpc.ContentBlock{MimeType: "image/jpeg", MediaType: "image/png"},
			wantType:   "image/jpeg",
			wantHinted: true,
		},
		{
			name:       "audio_type_fallback",
			block:      jsonrpc.ContentBlock{Type: "audio"},
			wantType:   "audio/unknown",
			wantHinted: true,
		},
		{
			name:       "video_type_fallback",
			block:      jsonrpc.ContentBlock{Type: "video"},
			wantType:   "video/unknown",
			wantHinted: true,
		},
		{
			name:       "image_type_fallback_empty_content_type",
			block:      jsonrpc.ContentBlock{Type: "image"},
			wantType:   "",
			wantHinted: true,
		},
		{
			name:       "image_type_with_content_type_hint",
			block:      jsonrpc.ContentBlock{Type: "image", MimeType: "image/webp"},
			wantType:   "image/webp",
			wantHinted: true,
		},
		{
			name:       "text_type_not_media",
			block:      jsonrpc.ContentBlock{Type: "text"},
			wantType:   "",
			wantHinted: false,
		},
		{
			name:       "empty_block",
			block:      jsonrpc.ContentBlock{},
			wantType:   "",
			wantHinted: false,
		},
		{
			name:       "mediaType_audio_with_params",
			block:      jsonrpc.ContentBlock{MediaType: "audio/mpeg; rate=44100"},
			wantType:   "audio/mpeg",
			wantHinted: true,
		},
		{
			name:       "non_media_mimeType_falls_through_to_type",
			block:      jsonrpc.ContentBlock{MimeType: "application/json", Type: "video"},
			wantType:   "video/unknown",
			wantHinted: true,
		},
		{
			name:       "non_media_mimeType_text_type",
			block:      jsonrpc.ContentBlock{MimeType: "application/json", Type: "text"},
			wantType:   "",
			wantHinted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotHinted := mcpMediaHint(tt.block)
			if gotType != tt.wantType {
				t.Errorf("mcpMediaHint() type = %q, want %q", gotType, tt.wantType)
			}
			if gotHinted != tt.wantHinted {
				t.Errorf("mcpMediaHint() hinted = %v, want %v", gotHinted, tt.wantHinted)
			}
		})
	}
}

func TestMCPMediaPayloadFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		block     jsonrpc.ContentBlock
		wantCount int
		wantNames []string
	}{
		{
			name:      "data_only",
			block:     jsonrpc.ContentBlock{Data: "aGVsbG8=", Type: "image", MimeType: "image/png"},
			wantCount: 1,
			wantNames: []string{"data"},
		},
		{
			name:      "blob_only",
			block:     jsonrpc.ContentBlock{Blob: "aGVsbG8=", Type: "image", MimeType: "image/png"},
			wantCount: 1,
			wantNames: []string{"blob"},
		},
		{
			name:      "data_and_blob_populated",
			block:     jsonrpc.ContentBlock{Data: "aGVsbG8=", Blob: "d29ybGQ=", Type: "image", MimeType: "image/png"},
			wantCount: 2,
			wantNames: []string{"data", "blob"},
		},
		{
			name:      "all_three_fields",
			block:     jsonrpc.ContentBlock{Data: "YQ==", Blob: "Yg==", Raw: "Yw==", Type: "image"},
			wantCount: 3,
			wantNames: []string{"data", "blob", "raw"},
		},
		{
			name:      "no_payload_fields",
			block:     jsonrpc.ContentBlock{Type: "text", Text: "hello"},
			wantCount: 0,
			wantNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields := mcpMediaPayloadFields(tt.block)
			if len(fields) != tt.wantCount {
				t.Fatalf("mcpMediaPayloadFields() returned %d fields, want %d", len(fields), tt.wantCount)
			}
			for i, wantName := range tt.wantNames {
				if fields[i].name != wantName {
					t.Errorf("field[%d].name = %q, want %q", i, fields[i].name, wantName)
				}
			}
		})
	}
}

func TestMCPContentBlockLooksLikeMedia(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		block jsonrpc.ContentBlock
		want  bool
	}{
		{
			name:  "image_type",
			block: jsonrpc.ContentBlock{Type: "image"},
			want:  true,
		},
		{
			name:  "audio_type",
			block: jsonrpc.ContentBlock{Type: "audio"},
			want:  true,
		},
		{
			name:  "video_type",
			block: jsonrpc.ContentBlock{Type: "video"},
			want:  true,
		},
		{
			name:  "text_type",
			block: jsonrpc.ContentBlock{Type: "text"},
			want:  false,
		},
		{
			name:  "media_mimeType_on_text_block",
			block: jsonrpc.ContentBlock{Type: "text", MimeType: "image/png"},
			want:  true,
		},
		{
			name:  "empty_block",
			block: jsonrpc.ContentBlock{},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mcpContentBlockLooksLikeMedia(tt.block)
			if got != tt.want {
				t.Errorf("mcpContentBlockLooksLikeMedia() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestForwardScanned_MediaPolicyBlocksVideo(t *testing.T) {
	sc, cfg := newMCPScannerWithMediaPolicy(t)
	line := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":99,"result":{"content":[{"type":"video","mimeType":"video/mp4","data":"%s"}]}}`,
		base64.StdEncoding.EncodeToString([]byte("fake video bytes")),
	)

	var out, log bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&out),
		&log,
		nil,
		MCPProxyOpts{
			Scanner:     sc,
			MediaPolicy: &cfg.MediaPolicy,
			Transport:   testMCPMediaTransport,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if found {
		t.Fatal("expected no injection finding for media-policy block")
	}

	var resp rpcError
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal block response: %v", err)
	}
	if string(resp.ID) != "99" {
		t.Fatalf("block response id = %s, want 99", string(resp.ID))
	}
}

func TestForwardScanned_MediaPolicyBlocksBlobOnlyField(t *testing.T) {
	sc, cfg := newMCPScannerWithMediaPolicy(t)
	line := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"audio","mimeType":"audio/wav","blob":"%s"}]}}`,
		base64.StdEncoding.EncodeToString([]byte("fake audio in blob")),
	)

	var out, log bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&out),
		&log,
		nil,
		MCPProxyOpts{
			Scanner:     sc,
			MediaPolicy: &cfg.MediaPolicy,
			Transport:   testMCPMediaTransport,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if found {
		t.Fatal("expected no injection finding for media-policy block")
	}

	var resp rpcError
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal block response: %v", err)
	}
	if string(resp.ID) != "7" {
		t.Fatalf("block response id = %s, want 7", string(resp.ID))
	}
}

func buildMCPValidJPEG(app1Payload []byte) []byte {
	writeSegmentLen := func(b *bytes.Buffer, length int) {
		if length < 0 || length > math.MaxUint16 {
			panic("buildMCPValidJPEG: segment length exceeds JPEG 16-bit limit")
		}
		b.WriteByte(byte(length >> 8))
		b.WriteByte(byte(length & 0xFF))
	}

	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8})
	jfif := []byte("JFIF header")
	b.Write([]byte{0xFF, 0xE0})
	writeSegmentLen(&b, len(jfif)+2)
	b.Write(jfif)
	b.Write([]byte{0xFF, 0xE1})
	writeSegmentLen(&b, len(app1Payload)+2)
	b.Write(app1Payload)
	b.Write([]byte{0xFF, 0xDA})
	b.Write([]byte{0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00})
	b.Write([]byte{0x11, 0x22, 0x33})
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}

func newMCPScannerWithMediaPolicy(t *testing.T) (*scanner.Scanner, *config.Config) {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	return sc, cfg
}

func TestForwardScanned_MediaPolicyStripsToolResultImage(t *testing.T) {
	sc, cfg := newMCPScannerWithMediaPolicy(t)
	jpeg := buildMCPValidJPEG([]byte("Exif\x00\x00mcp-secret-metadata"))
	line := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"image","mimeType":"image/jpeg","data":"%s"},{"type":"text","text":"safe"}]}}`,
		base64.StdEncoding.EncodeToString(jpeg),
	)

	var out, log bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&out),
		&log,
		nil,
		MCPProxyOpts{
			Scanner:     sc,
			MediaPolicy: &cfg.MediaPolicy,
			Transport:   transportMCPStdio,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if found {
		t.Fatal("expected no injection finding for media-only response")
	}

	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rpc); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	var result jsonrpc.ToolResult
	if err := json.Unmarshal(rpc.Result, &result); err != nil {
		t.Fatalf("unmarshal tool result: %v", err)
	}
	if len(result.Content) != 2 {
		t.Fatalf("content blocks = %d, want 2", len(result.Content))
	}
	if result.Content[1].Text != "safe" {
		t.Fatalf("text block = %q, want safe", result.Content[1].Text)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.Content[0].Data)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if bytes.Contains(decoded, []byte("mcp-secret-metadata")) {
		t.Fatal("stripped MCP image block still contains metadata payload")
	}
	if len(decoded) >= len(jpeg) {
		t.Fatalf("stripped MCP image length %d >= original %d", len(decoded), len(jpeg))
	}
}

func TestMCPContentTypeIsGeneric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mt   string
		want bool
	}{
		{name: "empty", mt: "", want: true},
		{name: "octet_stream", mt: "application/octet-stream", want: true},
		{name: "binary_octet_stream", mt: "binary/octet-stream", want: true},
		{name: "image_png", mt: "image/png", want: false},
		{name: "text_plain", mt: "text/plain", want: false},
		{name: "audio_mpeg", mt: "audio/mpeg", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mcpContentTypeIsGeneric(tt.mt)
			if got != tt.want {
				t.Errorf("mcpContentTypeIsGeneric(%q) = %v, want %v", tt.mt, got, tt.want)
			}
		})
	}
}

func TestSniffMCPMediaType(t *testing.T) {
	t.Parallel()

	// PNG magic: 8-byte header.
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	// JPEG magic: FF D8 FF.
	jpegMagic := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}

	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "empty", body: nil, want: ""},
		{name: "png_magic", body: pngMagic, want: "image/png"},
		{name: "jpeg_magic", body: jpegMagic, want: "image/jpeg"},
		{name: "plain_text", body: []byte("hello world this is plain text"), want: ""},
		{name: "short_png", body: pngMagic[:4], want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sniffMCPMediaType(tt.body)
			if got != tt.want {
				t.Errorf("sniffMCPMediaType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalMCPContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "simple", input: "image/png", want: "image/png"},
		{name: "with_params", input: "image/jpeg; quality=80", want: "image/jpeg"},
		{name: "uppercase", input: "IMAGE/PNG", want: "image/png"},
		{name: "invalid_with_semicolon", input: "bad type; extra", want: "bad type"},
		{name: "invalid_bare", input: "garbage", want: "garbage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := canonicalMCPContentType(tt.input)
			if got != tt.want {
				t.Errorf("canonicalMCPContentType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMCPExposureOrNil(t *testing.T) {
	t.Parallel()

	info := &audit.MediaExposureInfo{ContentType: "image/png"}

	t.Run("nil_policy", func(t *testing.T) {
		t.Parallel()
		got := mcpExposureOrNil(nil, info)
		if got != nil {
			t.Error("expected nil for nil policy")
		}
	})

	t.Run("logging_disabled", func(t *testing.T) {
		t.Parallel()
		disabled := false
		policy := &config.MediaPolicy{LogMediaExposure: &disabled}
		got := mcpExposureOrNil(policy, info)
		if got != nil {
			t.Error("expected nil when logging disabled")
		}
	})

	t.Run("logging_enabled", func(t *testing.T) {
		t.Parallel()
		policy := &config.MediaPolicy{LogMediaExposure: boolPtr(true)}
		got := mcpExposureOrNil(policy, info)
		if got == nil {
			t.Error("expected non-nil when logging enabled")
		}
	})
}

func TestApplyMCPMediaPolicy_NilPolicy(t *testing.T) {
	t.Parallel()

	verdict := applyMCPMediaPolicy(nil, "image/png", []byte("data"), testMCPMediaTransport)
	if verdict.Blocked {
		t.Error("nil policy should not block")
	}
}

func TestApplyMCPMediaPolicy_NonMediaType(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "text/plain", []byte("hello"), testMCPMediaTransport)
	if verdict.Blocked {
		t.Error("text/plain should not be blocked")
	}
}

func TestApplyMCPMediaPolicy_GenericContentTypeSniffsImage(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	// PNG magic bytes with generic content type -- should be sniffed.
	pngBody := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "application/octet-stream", pngBody, testMCPMediaTransport)
	if verdict.MediaType != "image/png" {
		t.Errorf("MediaType = %q, want image/png", verdict.MediaType)
	}
}

func TestApplyMCPMediaPolicy_AudioStripped(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.StripAudio = boolPtr(true)
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "audio/mpeg", []byte("audio-data"), testMCPMediaTransport)
	if !verdict.Blocked {
		t.Error("audio should be blocked when strip_audio is true")
	}
	if !strings.Contains(verdict.BlockReason, "audio stripped") {
		t.Errorf("BlockReason = %q, want 'audio stripped' substring", verdict.BlockReason)
	}
}

func TestApplyMCPMediaPolicy_AudioAllowed(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.StripAudio = boolPtr(false)
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "audio/mpeg", []byte("audio-data"), testMCPMediaTransport)
	if verdict.Blocked {
		t.Error("audio should not be blocked when strip_audio is false")
	}
}

func TestApplyMCPMediaPolicy_VideoStripped(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.StripVideo = boolPtr(true)
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "video/mp4", []byte("video-data"), testMCPMediaTransport)
	if !verdict.Blocked {
		t.Error("video should be blocked when strip_video is true")
	}
	if !strings.Contains(verdict.BlockReason, "video stripped") {
		t.Errorf("BlockReason = %q, want 'video stripped' substring", verdict.BlockReason)
	}
}

func TestApplyMCPMediaPolicy_VideoAllowed(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.StripVideo = boolPtr(false)
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "video/mp4", []byte("video-data"), testMCPMediaTransport)
	if verdict.Blocked {
		t.Error("video should not be blocked when strip_video is false")
	}
}

func TestApplyMCPMediaPolicy_ImageTypeNotAllowed(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.AllowedImageTypes = []string{"image/png"}
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "image/gif", []byte{0x47, 0x49, 0x46, 0x38}, testMCPMediaTransport)
	if !verdict.Blocked {
		t.Error("image/gif should be blocked when not in allowed list")
	}
	if !strings.Contains(verdict.BlockReason, "not in allowed list") {
		t.Errorf("BlockReason = %q, want 'not in allowed list' substring", verdict.BlockReason)
	}
}

func TestApplyMCPMediaPolicy_ImageTooLarge(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MediaPolicy.MaxImageBytes = 10
	// A body bigger than 10 bytes.
	bigBody := make([]byte, 20)
	verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, "image/png", bigBody, testMCPMediaTransport)
	if !verdict.Blocked {
		t.Error("oversized image should be blocked")
	}
	if !strings.Contains(verdict.BlockReason, "exceeds limit") {
		t.Errorf("BlockReason = %q, want 'exceeds limit' substring", verdict.BlockReason)
	}
}

func TestDecodeMCPMediaPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded string
		wantOK  bool
	}{
		{name: "empty", encoded: "", wantOK: false},
		{name: "whitespace_only", encoded: "   ", wantOK: false},
		{name: "valid_std_base64", encoded: base64.StdEncoding.EncodeToString([]byte("hello")), wantOK: true},
		{name: "valid_url_base64", encoded: base64.URLEncoding.EncodeToString([]byte("hello")), wantOK: true},
		{name: "invalid_base64", encoded: "!!!not-base64!!!", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := decodeMCPMediaPayload(tt.encoded)
			if ok != tt.wantOK {
				t.Errorf("decodeMCPMediaPayload() ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestApplyMCPResponseMediaPolicy_NilPolicy(t *testing.T) {
	t.Parallel()

	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	result := applyMCPResponseMediaPolicy(line, nil, testMCPMediaTransport)
	if result.Blocked {
		t.Error("nil policy should not block")
	}
	if result.Changed {
		t.Error("nil policy should not change line")
	}
}

func TestApplyMCPResponseMediaPolicy_InvalidJSON(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	line := []byte(`not valid json`)
	result := applyMCPResponseMediaPolicy(line, &cfg.MediaPolicy, testMCPMediaTransport)
	if result.Blocked {
		t.Error("invalid JSON should pass through unchanged")
	}
}

func TestApplyMCPResponseMediaPolicy_NoResult(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	line := []byte(`{"jsonrpc":"2.0","id":1}`)
	result := applyMCPResponseMediaPolicy(line, &cfg.MediaPolicy, testMCPMediaTransport)
	if result.Blocked || result.Changed {
		t.Error("missing result should pass through unchanged")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestForwardScanned_MediaPolicyBlocksToolResultAudio_EmitsReceipt(t *testing.T) {
	sc, cfg := newMCPScannerWithMediaPolicy(t)
	line := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":42,"result":{"content":[{"type":"audio","mimeType":"audio/mpeg","data":"%s"}]}}`,
		base64.StdEncoding.EncodeToString([]byte("fake audio bytes")),
	)

	emitter, rec, dir, pubHex := newReceiptTestHarness(t)
	var out, log bytes.Buffer
	found, err := ForwardScanned(
		transport.NewStdioReader(strings.NewReader(line+"\n")),
		transport.NewStdioWriter(&out),
		&log,
		nil,
		MCPProxyOpts{
			Scanner:        sc,
			MediaPolicy:    &cfg.MediaPolicy,
			ReceiptEmitter: emitter,
			Transport:      transportMCPStdio,
		},
	)
	if err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if found {
		t.Fatal("expected no injection finding for media-policy block")
	}

	var resp rpcError
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("unmarshal block response: %v", err)
	}
	if string(resp.ID) != "42" {
		t.Fatalf("block response id = %s, want 42", string(resp.ID))
	}

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	receipts := readActionReceipts(t, dir)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if err := receipt.VerifyWithKey(receipts[0], pubHex); err != nil {
		t.Fatalf("VerifyWithKey: %v", err)
	}
	if receipts[0].ActionRecord.Transport != transportMCPStdio {
		t.Fatalf("transport = %q, want %q", receipts[0].ActionRecord.Transport, transportMCPStdio)
	}
	if receipts[0].ActionRecord.Verdict != config.ActionBlock {
		t.Fatalf("verdict = %q, want %q", receipts[0].ActionRecord.Verdict, config.ActionBlock)
	}
	if receipts[0].ActionRecord.Layer != "media_policy" {
		t.Fatalf("layer = %q, want media_policy", receipts[0].ActionRecord.Layer)
	}
	if receipts[0].ActionRecord.Target != "response:42" {
		t.Fatalf("target = %q, want response:42", receipts[0].ActionRecord.Target)
	}
}
