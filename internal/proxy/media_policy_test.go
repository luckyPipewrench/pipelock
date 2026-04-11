// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// buildValidJPEG returns a minimal but structurally valid JPEG with an APP1
// (EXIF-style) segment whose payload is identifiable. The media package
// unit tests cover deeper parser behavior; this helper only needs a
// fixture the proxy media policy can route. Bounds-checks fixture sizes
// so the byte conversions cannot overflow JPEG's 16-bit length field.
func buildValidJPEG(app1Payload []byte) []byte {
	writeSegmentLen := func(b *bytes.Buffer, length int) {
		if length < 0 || length > math.MaxUint16 {
			panic("buildValidJPEG: segment length exceeds JPEG 16-bit limit")
		}
		b.WriteByte(byte(length >> 8))
		b.WriteByte(byte(length & 0xFF))
	}
	var b bytes.Buffer
	// SOI
	b.Write([]byte{0xFF, 0xD8})
	// APP0 JFIF (preserved)
	jfif := []byte("JFIF header")
	b.Write([]byte{0xFF, 0xE0})
	writeSegmentLen(&b, len(jfif)+2)
	b.Write(jfif)
	// APP1 EXIF (stripped)
	b.Write([]byte{0xFF, 0xE1})
	writeSegmentLen(&b, len(app1Payload)+2)
	b.Write(app1Payload)
	// SOS + trivial scan data + EOI
	b.Write([]byte{0xFF, 0xDA})
	b.Write([]byte{0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00})
	b.Write([]byte{0x11, 0x22, 0x33})
	b.Write([]byte{0xFF, 0xD9})
	return b.Bytes()
}

// buildValidPNG returns a minimal PNG with a tEXt metadata chunk.
func buildValidPNG(tEXtPayload []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	writeChunk := func(typ string, data []byte) {
		n := len(data)
		if n < 0 || n > math.MaxUint32 {
			panic("buildValidPNG: chunk data length out of uint32 range")
		}
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, uint32(n))
		b.Write(lenBytes)
		b.WriteString(typ)
		b.Write(data)
		crc := crc32.NewIEEE()
		_, _ = crc.Write([]byte(typ))
		_, _ = crc.Write(data)
		crcBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(crcBytes, crc.Sum32())
		b.Write(crcBytes)
	}
	writeChunk("IHDR", []byte("\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"))
	writeChunk("tEXt", tEXtPayload)
	writeChunk("IDAT", []byte("pixel bytes"))
	writeChunk("IEND", nil)
	return b.Bytes()
}

// TestApplyMediaPolicy_DisabledPassthrough verifies an explicit disable
// sets all branches to passthrough (no strip, no exposure).
func TestApplyMediaPolicy_DisabledPassthrough(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	f := false
	cfg.MediaPolicy.Enabled = &f
	body := buildValidJPEG([]byte("exif-payload"))
	v := applyMediaPolicy(cfg, "image/jpeg", body)
	if v.Blocked {
		t.Error("disabled policy must not block")
	}
	if v.StripResult != nil {
		t.Error("disabled policy must not run metadata surgery")
	}
	if v.Exposure != nil {
		t.Error("disabled policy must not emit exposure")
	}
	if !bytes.Equal(v.Body, body) {
		t.Error("disabled policy must return input bytes unchanged")
	}
}

// TestApplyMediaPolicy_NonMediaPassthrough verifies text/application types
// skip the media policy entirely.
func TestApplyMediaPolicy_NonMediaPassthrough(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	tests := []struct {
		ct   string
		body []byte
	}{
		{"text/html; charset=utf-8", []byte("<html></html>")},
		{"application/json", []byte(`{"k":"v"}`)},
		{"application/octet-stream", []byte{0x00, 0x01, 0x02}},
		{"", []byte("no content type")},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			v := applyMediaPolicy(cfg, tt.ct, tt.body)
			if v.Blocked {
				t.Errorf("non-media type %q was blocked", tt.ct)
			}
			if v.StripResult != nil {
				t.Errorf("non-media type %q produced a strip result", tt.ct)
			}
			if v.Exposure != nil {
				t.Errorf("non-media type %q produced exposure", tt.ct)
			}
			if !bytes.Equal(v.Body, tt.body) {
				t.Errorf("non-media type %q body changed", tt.ct)
			}
		})
	}
}

// TestApplyMediaPolicy_ImageStripsMetadata is the happy path: a valid JPEG
// with EXIF is allowed, metadata is stripped, exposure event payload is
// populated, and no block is issued.
func TestApplyMediaPolicy_ImageStripsMetadata(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	body := buildValidJPEG([]byte("Exif\x00\x00secret location data"))
	v := applyMediaPolicy(cfg, "image/jpeg", body)
	if v.Blocked {
		t.Fatalf("expected allowed, got blocked: %s", v.BlockReason)
	}
	if v.StripResult == nil || !v.StripResult.Changed() {
		t.Fatal("expected metadata strip to run and remove at least one segment")
	}
	if bytes.Contains(v.Body, []byte("secret location data")) {
		t.Error("stripped body still contains EXIF payload")
	}
	if v.Exposure == nil {
		t.Fatal("expected exposure event payload")
	}
	if v.Exposure.Format != "jpeg" {
		t.Errorf("exposure.Format = %q, want jpeg", v.Exposure.Format)
	}
	if v.Exposure.MetadataRemoved < 1 {
		t.Errorf("exposure.MetadataRemoved = %d, want >= 1", v.Exposure.MetadataRemoved)
	}
	if v.Exposure.Blocked {
		t.Error("exposure.Blocked = true on allowed path")
	}
}

// TestApplyMediaPolicy_ImageStripsPNGMetadata exercises the PNG path.
func TestApplyMediaPolicy_ImageStripsPNGMetadata(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	body := buildValidPNG([]byte("Description\x00author=Eve\x00steg-data"))
	v := applyMediaPolicy(cfg, "image/png", body)
	if v.Blocked {
		t.Fatalf("expected allowed, got blocked: %s", v.BlockReason)
	}
	if v.StripResult == nil || !v.StripResult.Changed() {
		t.Fatal("expected PNG metadata strip to remove a chunk")
	}
	if bytes.Contains(v.Body, []byte("steg-data")) {
		t.Error("stripped PNG still contains tEXt payload")
	}
	if v.Exposure == nil {
		t.Error("expected exposure payload on allowed PNG")
	} else if v.Exposure.Format != "png" {
		t.Errorf("exposure.Format = %q, want png", v.Exposure.Format)
	}
}

// TestApplyMediaPolicy_ImageSizeLimit verifies oversize images are blocked
// before parsing (decompression bomb defense).
func TestApplyMediaPolicy_ImageSizeLimit(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.MediaPolicy.MaxImageBytes = 128 // tiny cap
	body := make([]byte, 256)
	// Valid SOI prefix so we fail on size, not format.
	body[0] = 0xFF
	body[1] = 0xD8
	v := applyMediaPolicy(cfg, "image/jpeg", body)
	if !v.Blocked {
		t.Fatal("expected oversize image to be blocked")
	}
	if !strings.Contains(v.BlockReason, "exceeds limit") {
		t.Errorf("block reason = %q, want size-limit message", v.BlockReason)
	}
	if v.Exposure == nil {
		t.Error("expected exposure payload on block")
	}
}

// TestApplyMediaPolicy_ImageTypeNotAllowed verifies image types outside the
// allowlist are blocked.
func TestApplyMediaPolicy_ImageTypeNotAllowed(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	// Narrow the allowlist to PNG only.
	cfg.MediaPolicy.AllowedImageTypes = []string{"image/png"}
	v := applyMediaPolicy(cfg, "image/jpeg", []byte{0xFF, 0xD8})
	if !v.Blocked {
		t.Fatal("expected jpeg to be blocked with png-only allowlist")
	}
	if !strings.Contains(v.BlockReason, "not in allowed list") {
		t.Errorf("block reason = %q, want allowlist message", v.BlockReason)
	}
}

// TestApplyMediaPolicy_StripImages verifies the blanket image strip mode.
func TestApplyMediaPolicy_StripImages(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	tr := true
	cfg.MediaPolicy.StripImages = &tr
	v := applyMediaPolicy(cfg, "image/png", []byte{0x89, 0x50, 0x4E, 0x47})
	if !v.Blocked {
		t.Fatal("expected png to be blocked under strip_images")
	}
	if !strings.Contains(v.BlockReason, "images stripped") {
		t.Errorf("block reason = %q, want strip-images message", v.BlockReason)
	}
}

// TestApplyMediaPolicy_AudioVideoBlock verifies audio and video are blocked
// by the default policy.
func TestApplyMediaPolicy_AudioVideoBlock(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	audio := applyMediaPolicy(cfg, "audio/mpeg", []byte("fake audio"))
	if !audio.Blocked {
		t.Error("expected audio to be blocked by default policy")
	}
	if !strings.Contains(audio.BlockReason, "audio stripped") {
		t.Errorf("audio block reason = %q", audio.BlockReason)
	}
	video := applyMediaPolicy(cfg, "video/mp4", []byte("fake video"))
	if !video.Blocked {
		t.Error("expected video to be blocked by default policy")
	}
	if !strings.Contains(video.BlockReason, "video stripped") {
		t.Errorf("video block reason = %q", video.BlockReason)
	}
}

// TestApplyMediaPolicy_AudioVideoAllowed verifies explicit opt-in allows
// audio and video.
func TestApplyMediaPolicy_AudioVideoAllowed(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	f := false
	cfg.MediaPolicy.StripAudio = &f
	cfg.MediaPolicy.StripVideo = &f
	audio := applyMediaPolicy(cfg, "audio/mpeg", []byte("ok"))
	if audio.Blocked {
		t.Error("audio should pass when strip_audio=false")
	}
	video := applyMediaPolicy(cfg, "video/mp4", []byte("ok"))
	if video.Blocked {
		t.Error("video should pass when strip_video=false")
	}
}

// TestApplyMediaPolicy_ParseErrorFailsClosed verifies a malformed image
// body is blocked, not forwarded. This is the fail-closed invariant:
// content we cannot parse is content we cannot clean.
func TestApplyMediaPolicy_ParseErrorFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	// Wrong prefix — media.StripMetadata returns ErrInvalidJPEG.
	v := applyMediaPolicy(cfg, "image/jpeg", []byte{0x00, 0x01, 0x02, 0x03})
	if !v.Blocked {
		t.Fatal("malformed jpeg must be blocked (fail-closed)")
	}
	if !strings.Contains(v.BlockReason, "parse error") {
		t.Errorf("block reason = %q, want parse error", v.BlockReason)
	}
}

// TestApplyMediaPolicy_LogExposureToggle verifies nil exposure when
// log_media_exposure is explicitly disabled.
func TestApplyMediaPolicy_LogExposureToggle(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	f := false
	cfg.MediaPolicy.LogMediaExposure = &f
	body := buildValidJPEG([]byte("Exif\x00\x00payload"))
	v := applyMediaPolicy(cfg, "image/jpeg", body)
	if v.Blocked {
		t.Fatal("unexpected block")
	}
	if v.Exposure != nil {
		t.Error("expected Exposure nil when log_media_exposure=false")
	}
}

// TestApplyMediaPolicy_MetadataStripToggle verifies strip_image_metadata
// false preserves the original body (no surgery).
func TestApplyMediaPolicy_MetadataStripToggle(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	f := false
	cfg.MediaPolicy.StripImageMetadata = &f
	body := buildValidJPEG([]byte("Exif\x00\x00payload"))
	v := applyMediaPolicy(cfg, "image/jpeg", body)
	if v.Blocked {
		t.Fatal("unexpected block")
	}
	if v.StripResult != nil {
		t.Error("expected StripResult nil when strip_image_metadata=false")
	}
	if !bytes.Equal(v.Body, body) {
		t.Error("body modified despite strip_image_metadata=false")
	}
	if v.Exposure == nil {
		t.Error("exposure should still fire (log_media_exposure=true)")
	}
}

// TestApplyMediaPolicy_NilConfig verifies the nil-safe defensive passthrough.
func TestApplyMediaPolicy_NilConfig(t *testing.T) {
	t.Parallel()
	body := []byte("anything")
	v := applyMediaPolicy(nil, "image/jpeg", body)
	if v.Blocked {
		t.Error("nil config must passthrough, not block")
	}
	if !bytes.Equal(v.Body, body) {
		t.Error("nil config modified body")
	}
}

// TestMediaExposureFields_ToEventFields verifies the structured field map
// includes the expected keys and omits empty values.
func TestMediaExposureFields_ToEventFields(t *testing.T) {
	t.Parallel()
	minimal := &MediaExposureFields{
		ContentType: "image/jpeg",
		SizeBytes:   1024,
	}
	f := minimal.ToEventFields()
	if f["content_type"] != "image/jpeg" {
		t.Error("content_type missing")
	}
	if f["size_bytes"].(int) != 1024 {
		t.Error("size_bytes missing")
	}
	if _, ok := f["metadata_segments_removed"]; ok {
		t.Error("metadata_segments_removed should be omitted when 0")
	}
	if _, ok := f["block_reason"]; ok {
		t.Error("block_reason should be omitted when empty")
	}
	full := &MediaExposureFields{
		ContentType:     "image/png",
		SizeBytes:       2048,
		Format:          "png",
		MetadataRemoved: 3,
		BytesRemoved:    120,
		Blocked:         true,
		BlockReason:     "test",
	}
	f = full.ToEventFields()
	if f["format"] != "png" {
		t.Error("format missing")
	}
	if f["metadata_segments_removed"].(int) != 3 {
		t.Error("metadata_segments_removed missing")
	}
	if f["block_reason"] != "test" {
		t.Error("block_reason missing")
	}
}

// TestForwardHTTP_MediaPolicyStripsJPEGMetadata is the transport-integration
// test: a real forward proxy with a backend that serves a JPEG containing
// an APP1 segment, verifying the forwarded response has the metadata
// elided byte-level. This proves the applyMediaPolicy wire in forward.go
// runs on real responses and replaces the body.
func TestForwardHTTP_MediaPolicyStripsJPEGMetadata(t *testing.T) {
	secretPayload := []byte("Exif\x00\x00gps:51.5074,-0.1278:ThisIsPrivate")
	jpegBytes := buildValidJPEG(secretPayload)

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpegBytes)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/image.jpg")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bytes.Contains(body, secretPayload) {
		t.Errorf("forwarded JPEG still contains EXIF payload — media policy did not run")
	}
	if !bytes.HasPrefix(body, []byte{0xFF, 0xD8}) {
		t.Error("forwarded body is not a JPEG (missing SOI)")
	}
	if len(body) >= len(jpegBytes) {
		t.Errorf("stripped body length %d >= original %d; no bytes removed", len(body), len(jpegBytes))
	}
}

// TestForwardHTTP_MediaPolicyBlocksAudio verifies the default policy rejects
// audio responses forwarded through the proxy.
func TestForwardHTTP_MediaPolicyBlocksAudio(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("fake audio payload that should never reach the agent"))
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/audio.mp3")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for audio, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "audio stripped") {
		t.Errorf("expected audio block reason in body, got: %s", body)
	}
}

// fakeMediaLogger records LogMediaExposure calls for assertion.
type fakeMediaLogger struct {
	calls []audit.MediaExposureInfo
}

func (f *fakeMediaLogger) LogMediaExposure(_ audit.LogContext, info audit.MediaExposureInfo) {
	f.calls = append(f.calls, info)
}

// TestLogMediaExposureIfPresent_EmitsWithTransport verifies that a verdict
// carrying an exposure payload produces exactly one LogMediaExposure call
// and the transport tag is passed through unchanged. Also checks that nil
// exposure and nil logger are safe no-ops (never panic, never emit).
func TestLogMediaExposureIfPresent_EmitsWithTransport(t *testing.T) {
	t.Parallel()
	v := MediaPolicyVerdict{
		MediaType: "image/jpeg",
		Exposure: &MediaExposureFields{
			ContentType: "image/jpeg",
			SizeBytes:   2048,
			Format:      "jpeg",
		},
	}
	logger := &fakeMediaLogger{}
	actx, err := audit.NewHTTPLogContext(http.MethodGet, "https://example.com/x.jpg", "127.0.0.1", "req-media-1", "")
	if err != nil {
		t.Fatal(err)
	}
	logMediaExposureIfPresent(logger, actx, v, "reverse")
	if len(logger.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(logger.calls))
	}
	if logger.calls[0].Transport != "reverse" {
		t.Errorf("Transport = %q, want reverse", logger.calls[0].Transport)
	}
	if logger.calls[0].Format != "jpeg" {
		t.Errorf("Format = %q, want jpeg", logger.calls[0].Format)
	}
}

func TestLogMediaExposureIfPresent_NoExposureNoCall(t *testing.T) {
	t.Parallel()
	logger := &fakeMediaLogger{}
	logMediaExposureIfPresent(logger, audit.LogContext{}, MediaPolicyVerdict{MediaType: "text/html"}, "forward")
	if len(logger.calls) != 0 {
		t.Errorf("nil exposure produced %d calls, want 0", len(logger.calls))
	}
}

func TestLogMediaExposureIfPresent_NilLoggerSafe(t *testing.T) {
	t.Parallel()
	v := MediaPolicyVerdict{Exposure: &MediaExposureFields{}}
	// Must not panic — transports may be wired before the logger is
	// initialized during startup.
	logMediaExposureIfPresent(nil, audit.LogContext{}, v, "forward")
}

// TestFetchEndpoint_MediaPolicyStripsJPEG exercises the fetch-endpoint
// wire by calling handleFetch against an httptest backend that serves a
// JPEG containing an APP1 payload. Parity coverage with forward.go.
//
// The fetch endpoint JSON-encodes the binary body into FetchResponse.Content,
// which escapes control characters (\x00 → \u0000). Asserting on raw response
// bytes would be a false negative — the substring "Exif\x00\x00..." can never
// appear unescaped in the JSON. Decode the response and check the Content
// field directly, plus the printable suffix of the payload.
func TestFetchEndpoint_MediaPolicyStripsJPEG(t *testing.T) {
	const payloadTail = "fetch-path-secret-tail"
	secretPayload := []byte("Exif\x00\x00" + payloadTail)
	jpegBytes := buildValidJPEG(secretPayload)

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpegBytes)
	}))
	defer backend.Close()

	p, b := setupTestProxy(t)
	defer b.Close()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/photo.jpg", nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode FetchResponse: %v", err)
	}
	if resp.Blocked {
		t.Errorf("response marked blocked: %s", resp.BlockReason)
	}
	// The printable tail is the only portion of the payload that can
	// survive JSON encoding as-is. If media policy stripped APP1,
	// neither the tail nor the escaped leading bytes should appear in
	// the decoded Content.
	if strings.Contains(resp.Content, payloadTail) {
		t.Errorf("decoded FetchResponse.Content still contains EXIF tail %q", payloadTail)
	}
}

// TestFetchEndpoint_MediaPolicyBlocksAudio proves the fetch endpoint
// blocks audio responses and returns a structured FetchResponse.
func TestFetchEndpoint_MediaPolicyBlocksAudio(t *testing.T) {
	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("audio response bytes"))
	}))
	defer backend.Close()

	p, b := setupTestProxy(t)
	defer b.Close()

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+backend.URL+"/track.mp3", nil)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "audio stripped") {
		t.Errorf("expected audio block reason, got: %s", w.Body.String())
	}
}

// TestReverseProxy_MediaPolicyStripsJPEG proves the reverse proxy path
// calls the media policy helper. Uses reverseTestSetup from reverse_test.go.
func TestReverseProxy_MediaPolicyStripsJPEG(t *testing.T) {
	secretPayload := []byte("Exif\x00\x00reverse-path-secret")
	jpegBytes := buildValidJPEG(secretPayload)

	cfg := reverseTestConfig()
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jpegBytes)
	}
	proxy := reverseTestSetup(t, cfg, upstream)

	resp := testGet(t, proxy.URL+"/img.jpg")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, secretPayload) {
		t.Error("reverse proxy still forwarded EXIF payload after media policy")
	}
	if len(body) >= len(jpegBytes) {
		t.Errorf("body length %d >= original %d (no strip)", len(body), len(jpegBytes))
	}
}

// TestReverseProxy_MediaPolicyStripsWhenResponseScanDisabled regressions
// the bypass where disabling response_scanning silently turned off media
// policy because modifyResponse returned early before the media branch.
// Media policy must run regardless of response-scanning state.
func TestReverseProxy_MediaPolicyStripsWhenResponseScanDisabled(t *testing.T) {
	secretPayload := []byte("Exif\x00\x00scan-disabled-leak")
	jpegBytes := buildValidJPEG(secretPayload)

	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = false
	// MediaPolicy defaults remain enabled.

	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jpegBytes)
	}
	proxy := reverseTestSetup(t, cfg, upstream)

	resp := testGet(t, proxy.URL+"/img.jpg")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, secretPayload) {
		t.Error("media policy did NOT run when response_scanning was disabled — bypass regression")
	}
}

// TestReverseProxy_MediaPolicyBlocksAudioWhenResponseScanDisabled same
// regression for the block path.
func TestReverseProxy_MediaPolicyBlocksAudioWhenResponseScanDisabled(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.BrowserShield.Enabled = false

	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("audio should never reach the agent"))
	}
	proxy := reverseTestSetup(t, cfg, upstream)

	resp := testGet(t, proxy.URL+"/song.mp3")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when response_scanning disabled, got %d (media policy bypass)", resp.StatusCode)
	}
}

// TestForwardHTTP_MediaPolicyStripsWhenResponseScanDisabled regressions
// the same bypass on the forward proxy. The original gate was
// `if sc.ResponseScanningEnabled() || cfg.BrowserShield.Enabled` — media
// policy never buffered the body when both were off.
func TestForwardHTTP_MediaPolicyStripsWhenResponseScanDisabled(t *testing.T) {
	secretPayload := []byte("Exif\x00\x00forward-scan-disabled-leak")
	jpegBytes := buildValidJPEG(secretPayload)

	backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write(jpegBytes)
	}))
	defer backend.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
		cfg.BrowserShield.Enabled = false
	})
	defer cleanup()

	client := proxyClient(proxyAddr)
	resp := doGet(t, client, backend.URL+"/image.jpg")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if bytes.Contains(body, secretPayload) {
		t.Error("forward proxy did NOT run media policy when response_scanning and shield were disabled — bypass regression")
	}
}

// TestReverseProxy_MediaPolicyBlocksAudio proves the reverse proxy
// rejects audio by default.
func TestReverseProxy_MediaPolicyBlocksAudio(t *testing.T) {
	cfg := reverseTestConfig()
	upstream := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake audio payload"))
	}
	proxy := reverseTestSetup(t, cfg, upstream)

	resp := testGet(t, proxy.URL+"/track.mp3")
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for audio response, got %d", resp.StatusCode)
	}
}

// TestApplyMediaPolicy_HeaderSpoofingBypassBlocked regressions the
// Content-Type spoofing bypass: an attacker who serves a JPEG with
// Content-Type: application/octet-stream (or empty) should not skip
// the image metadata strip. Content sniffing runs on generic/missing
// declarations and brings spoofed media under policy enforcement.
func TestApplyMediaPolicy_HeaderSpoofingBypassBlocked(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	jpegBytes := buildValidJPEG([]byte("Exif\x00\x00spoofed-metadata"))

	tests := []struct {
		name string
		ct   string
	}{
		{"empty content-type", ""},
		{"application/octet-stream", "application/octet-stream"},
		{"binary/octet-stream", "binary/octet-stream"},
		{"application/binary", "application/binary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := applyMediaPolicy(cfg, tt.ct, jpegBytes)
			if v.Blocked {
				t.Fatalf("expected allowed (with strip), got blocked: %s", v.BlockReason)
			}
			if v.StripResult == nil || !v.StripResult.Changed() {
				t.Fatal("expected metadata strip to run on sniffed image body")
			}
			if bytes.Contains(v.Body, []byte("spoofed-metadata")) {
				t.Error("sniffed image body still contains EXIF payload — spoofing bypass regression")
			}
			if v.Exposure == nil {
				t.Error("expected exposure payload on sniffed image")
			}
		})
	}
}

// TestApplyMediaPolicy_ExplicitNonMediaNotSniffed verifies that an
// explicit non-generic declaration (e.g. text/html) is NOT overridden by
// content sniffing. The spoofing defense is scoped to generic/empty
// declarations; honoring explicit non-media claims preserves legitimate
// upstream behavior.
func TestApplyMediaPolicy_ExplicitNonMediaNotSniffed(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	jpegBytes := buildValidJPEG([]byte("Exif\x00\x00payload"))
	v := applyMediaPolicy(cfg, "text/html; charset=utf-8", jpegBytes)
	if v.Blocked {
		t.Errorf("text/html declaration should passthrough, got block: %s", v.BlockReason)
	}
	if v.StripResult != nil {
		t.Error("text/html declaration should NOT trigger metadata strip via sniffing")
	}
	if !bytes.Equal(v.Body, jpegBytes) {
		t.Error("body modified despite explicit non-media declaration")
	}
}

// TestCanonicalContentType covers the parse-error fallback branch.
func TestCanonicalContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"image/jpeg", "image/jpeg"},
		{"IMAGE/JPEG; charset=binary", "image/jpeg"},
		{"", ""},
		{"  image/png  ", "image/png"},
		{"malformed;;", "malformed"},
		{"no-slash", "no-slash"}, // parse error → naive fallback
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := canonicalContentType(tt.in)
			if got != tt.want {
				t.Errorf("canonicalContentType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
