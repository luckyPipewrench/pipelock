// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"testing"
)

// --- JPEG fixtures ---

// buildJPEG assembles a synthetic JPEG byte stream with SOI, a list of
// marker segments, a minimal SOS + scan data, and EOI. Each input segment
// is (marker, payload). Length bytes are added automatically and include
// the length field themselves, per JPEG spec. Bounds-checks fixture sizes
// so the []byte conversions cannot silently overflow.
func buildJPEG(segments [][2]any) []byte {
	var b bytes.Buffer
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOI)
	for _, seg := range segments {
		markerInt := seg[0].(int)
		if markerInt < 0 || markerInt > 0xFF {
			panic("buildJPEG: marker out of byte range")
		}
		payload, _ := seg[1].([]byte)
		length := len(payload) + 2 // include the 2 length bytes
		if length < 0 || length > math.MaxUint16 {
			panic("buildJPEG: segment length exceeds JPEG 16-bit limit")
		}
		b.WriteByte(0xFF)
		b.WriteByte(byte(markerInt))
		b.WriteByte(byte(length >> 8))
		b.WriteByte(byte(length & 0xFF))
		b.Write(payload)
	}
	// Append a minimal SOS + trivial scan data so the parser walks the
	// full structure, then EOI.
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOS)
	// SOS header: length field (2) + component count (1) + component data
	// (2) + Ss Se Ah (3) = 8 byte payload + length = 10 byte segment.
	sosHeader := []byte{0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00}
	b.Write(sosHeader)
	// Minimal scan data with one restart marker and byte-stuffing to
	// exercise the scan-walk logic.
	b.Write([]byte{0x11, 0x22, 0xFF, 0x00, 0x33, 0xFF, 0xD0, 0x44})
	b.WriteByte(0xFF)
	b.WriteByte(jpegEOI)
	return b.Bytes()
}

func TestStripJPEG_RemovesAPP1APP2APP13(t *testing.T) {
	t.Parallel()
	input := buildJPEG([][2]any{
		{int(jpegAPP0), []byte("JFIF header stays")},
		{int(jpegAPP1), []byte("Exif\x00\x00fake exif payload")},
		{int(jpegAPP2), []byte("ICC_PROFILE\x00\x00fake icc")},
		{int(jpegAPP13), []byte("Photoshop 3.0\x00iptc stuff")},
		{0xE4, []byte("APP4 passthrough")},
	})
	res, err := stripJPEG(input)
	if err != nil {
		t.Fatalf("stripJPEG: %v", err)
	}
	if !res.Changed() {
		t.Fatalf("expected Changed() true, got false")
	}
	if res.SegmentsRemoved != 3 {
		t.Errorf("SegmentsRemoved = %d, want 3", res.SegmentsRemoved)
	}
	if res.BytesRemoved <= 0 {
		t.Errorf("BytesRemoved = %d, want > 0", res.BytesRemoved)
	}
	if res.Format != "jpeg" {
		t.Errorf("Format = %q, want jpeg", res.Format)
	}

	// Output must not contain any of the stripped payloads.
	for _, needle := range [][]byte{
		[]byte("fake exif payload"),
		[]byte("fake icc"),
		[]byte("iptc stuff"),
	} {
		if bytes.Contains(res.Data, needle) {
			t.Errorf("output still contains stripped payload %q", needle)
		}
	}

	// Output must contain preserved segments.
	for _, needle := range [][]byte{
		[]byte("JFIF header stays"),
		[]byte("APP4 passthrough"),
	} {
		if !bytes.Contains(res.Data, needle) {
			t.Errorf("output missing preserved payload %q", needle)
		}
	}

	// EOI must be present at the end.
	if len(res.Data) < 2 || res.Data[len(res.Data)-2] != 0xFF || res.Data[len(res.Data)-1] != jpegEOI {
		t.Errorf("output does not end with EOI")
	}
}

func TestStripJPEG_NoMetadataIsIdentical(t *testing.T) {
	t.Parallel()
	// Input has only APP0 (preserved) and no APP1/APP2/APP13.
	input := buildJPEG([][2]any{
		{int(jpegAPP0), []byte("JFIF only")},
	})
	res, err := stripJPEG(input)
	if err != nil {
		t.Fatalf("stripJPEG: %v", err)
	}
	if res.Changed() {
		t.Errorf("expected no changes, got SegmentsRemoved=%d BytesRemoved=%d", res.SegmentsRemoved, res.BytesRemoved)
	}
	if !bytes.Equal(res.Data, input) {
		t.Errorf("output differs from input despite no strip markers")
	}
}

// TestStripJPEG_RejectsAppOnlyFile verifies that a JPEG stream without any
// SOS marker fails closed. A structurally valid JPEG must contain a Start
// of Scan segment followed by entropy-coded image data; a header-only
// input is not a renderable image and must be rejected so the media-policy
// parse-error branch can fail closed on the response.
func TestStripJPEG_RejectsAppOnlyFile(t *testing.T) {
	t.Parallel()
	// Build SOI + APP1 + EOI by hand (buildJPEG always appends SOS).
	var b bytes.Buffer
	b.Write([]byte{0xFF, 0xD8})
	b.Write([]byte{0xFF, 0xE1}) // APP1
	payload := []byte("Exif\x00\x00payload")
	length := len(payload) + 2
	// Must panic on out-of-range (not t.Fatalf) so gosec's SSA value-range
	// analysis narrows `length` to a uint16-safe interval before the
	// narrowing casts below. t.Fatalf doesn't terminate early enough for
	// gosec's control-flow tracking.
	if length < 0 || length > math.MaxUint16 {
		panic("buildJPEG fixture: length out of JPEG 16-bit range")
	}
	b.WriteByte(byte(length >> 8))
	b.WriteByte(byte(length & 0xFF))
	b.Write(payload)
	b.Write([]byte{0xFF, 0xD9}) // EOI
	_, err := stripJPEG(b.Bytes())
	if err == nil {
		t.Fatal("expected ErrInvalidJPEG for APP-only stream")
	}
	if !errors.Is(err, ErrInvalidJPEG) {
		t.Errorf("error = %v, want ErrInvalidJPEG wrap", err)
	}
}

func TestStripJPEG_InvalidInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0xFF}},
		{"wrong prefix", []byte{0x00, 0x00, 0x00, 0x00}},
		{"SOI only then garbage", []byte{0xFF, 0xD8, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := stripJPEG(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidJPEG) {
				t.Errorf("error = %v, want ErrInvalidJPEG wrap", err)
			}
		})
	}
}

// TestStripJPEG_TruncatedAfterSOS exercises the graceful path where a scan
// data stream is truncated before the next marker. The parser must return
// TestStripJPEG_TruncatedAfterSOS asserts that a JPEG whose entropy-coded
// scan data runs past the end of the buffer without ever hitting EOI is
// rejected. Fail-closed is correct here: the downstream caller cannot
// meaningfully forward a half-written image, and returning a "successful"
// strip on truncated input would bypass the media-policy parse-error
// branch.
func TestStripJPEG_TruncatedAfterSOS(t *testing.T) {
	t.Parallel()
	// Manually construct SOI + SOS header + truncated scan data (no EOI).
	b := bytes.Buffer{}
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOI)
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOS)
	b.Write([]byte{0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00})
	b.Write([]byte{0x11, 0x22, 0xFF}) // single 0xFF, no following marker byte
	_, err := stripJPEG(b.Bytes())
	if err == nil {
		t.Fatal("expected ErrInvalidJPEG for truncated scan data")
	}
	if !errors.Is(err, ErrInvalidJPEG) {
		t.Errorf("error = %v, want ErrInvalidJPEG wrap", err)
	}
}

// TestStripJPEG_NoEOI asserts that a JPEG with a clean scan stream but no
// EOI marker fails closed. The scan walk currently ends cleanly when EOF
// is reached mid-segment, and without the EOI requirement that would
// silently produce a half-written result.
func TestStripJPEG_NoEOI(t *testing.T) {
	t.Parallel()
	// SOI + SOS header + a few bytes of entropy-coded scan data that
	// terminates without any trailing 0xFF marker.
	b := bytes.Buffer{}
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOI)
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOS)
	b.Write([]byte{0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x3F, 0x00})
	b.Write([]byte{0x11, 0x22, 0x33, 0x44, 0x55}) // clean run, no FF
	_, err := stripJPEG(b.Bytes())
	if err == nil {
		t.Fatal("expected ErrInvalidJPEG when EOI is missing")
	}
	if !errors.Is(err, ErrInvalidJPEG) {
		t.Errorf("error = %v, want ErrInvalidJPEG wrap", err)
	}
}

// --- PNG fixtures ---

// buildPNG assembles a synthetic PNG byte stream with the signature, a list
// of chunks, and a terminating IEND. Each input chunk is (type, data) and
// the helper computes the length and CRC fields.
func buildPNG(chunks [][2]any) []byte {
	var b bytes.Buffer
	b.Write(pngSignature)
	for _, ch := range chunks {
		typ := ch[0].(string)
		data, _ := ch[1].([]byte)
		n := len(data)
		if n < 0 || n > math.MaxUint32 {
			panic("buildPNG: chunk data length out of uint32 range")
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
	// Terminating IEND chunk (length 0, type IEND, CRC computed).
	b.Write([]byte{0x00, 0x00, 0x00, 0x00})
	b.WriteString("IEND")
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte("IEND"))
	crcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBytes, crc.Sum32())
	b.Write(crcBytes)
	return b.Bytes()
}

func TestStripPNG_RemovesTextChunks(t *testing.T) {
	t.Parallel()
	input := buildPNG([][2]any{
		{"IHDR", []byte("\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")},
		{"tEXt", []byte("Author\x00Steganographer")},
		{"iTXt", []byte("Description\x00\x00\x00\x00\x00international comment payload")},
		{"zTXt", []byte("Keyword\x00\x00compressed")},
		{"eXIf", []byte("fake exif bytes")},
		{"IDAT", []byte("fake pixel data")},
	})
	res, err := stripPNG(input)
	if err != nil {
		t.Fatalf("stripPNG: %v", err)
	}
	if !res.Changed() {
		t.Fatal("expected Changed() true")
	}
	if res.SegmentsRemoved != 4 {
		t.Errorf("SegmentsRemoved = %d, want 4", res.SegmentsRemoved)
	}
	if res.BytesRemoved <= 0 {
		t.Errorf("BytesRemoved = %d, want > 0", res.BytesRemoved)
	}
	if res.Format != "png" {
		t.Errorf("Format = %q, want png", res.Format)
	}

	// Stripped content must not appear in the output.
	for _, needle := range [][]byte{
		[]byte("Steganographer"),
		[]byte("international comment payload"),
		[]byte("compressed"),
		[]byte("fake exif bytes"),
		[]byte("tEXt"),
		[]byte("iTXt"),
		[]byte("zTXt"),
		[]byte("eXIf"),
	} {
		if bytes.Contains(res.Data, needle) {
			t.Errorf("output still contains stripped %q", needle)
		}
	}

	// Preserved content must remain.
	if !bytes.Contains(res.Data, []byte("fake pixel data")) {
		t.Error("output missing IDAT payload")
	}
	if !bytes.Contains(res.Data, []byte("IHDR")) {
		t.Error("output missing IHDR")
	}
	if !bytes.Contains(res.Data, []byte("IEND")) {
		t.Error("output missing IEND")
	}
}

func TestStripPNG_NoMetadataIsIdentical(t *testing.T) {
	t.Parallel()
	input := buildPNG([][2]any{
		{"IHDR", []byte("\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")},
		{"IDAT", []byte("fake idat bytes")},
	})
	res, err := stripPNG(input)
	if err != nil {
		t.Fatalf("stripPNG: %v", err)
	}
	if res.Changed() {
		t.Errorf("expected no changes, got SegmentsRemoved=%d", res.SegmentsRemoved)
	}
	if !bytes.Equal(res.Data, input) {
		t.Error("output bytes differ from input despite no strip chunks")
	}
}

// TestStripPNG_RejectsMissingIEND verifies that a PNG stream which never
// reaches IEND fails closed. Without the IEND check the truncated file
// would return a bogus "successful" strip result that bypasses the
// media-policy parse-error branch.
func TestStripPNG_RejectsMissingIEND(t *testing.T) {
	t.Parallel()
	// Build signature + IHDR + IDAT with NO IEND chunk.
	var b bytes.Buffer
	b.Write(pngSignature)
	writeChunk := func(typ string, data []byte) {
		n := len(data)
		if n < 0 || n > math.MaxUint32 {
			panic("length overflow")
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
	writeChunk("IDAT", []byte("fake pixel data"))
	// Deliberately omit IEND.

	_, err := stripPNG(b.Bytes())
	if err == nil {
		t.Fatal("expected ErrInvalidPNG for stream without IEND")
	}
	if !errors.Is(err, ErrInvalidPNG) {
		t.Errorf("error = %v, want ErrInvalidPNG wrap", err)
	}
}

func TestStripPNG_InvalidInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"short signature", []byte{0x89, 0x50}},
		{"wrong signature", bytes.Repeat([]byte{0x00}, 8)},
		{"truncated chunk header", append(append([]byte{}, pngSignature...), 0x00, 0x00, 0x00)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := stripPNG(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidPNG) {
				t.Errorf("error = %v, want ErrInvalidPNG wrap", err)
			}
		})
	}
}

// TestStripPNG_ChunkLengthOverrun verifies that a chunk whose declared
// length extends beyond the input buffer is rejected rather than silently
// truncated. This prevents malicious PNGs from causing out-of-bounds reads.
func TestStripPNG_ChunkLengthOverrun(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	b.Write(pngSignature)
	// Declare a chunk with length 1 << 20 but provide no data.
	b.Write([]byte{0x00, 0x10, 0x00, 0x00})
	b.WriteString("tEXt")
	// No payload or CRC.
	_, err := stripPNG(b.Bytes())
	if err == nil {
		t.Fatal("expected overrun error, got nil")
	}
	if !errors.Is(err, ErrInvalidPNG) {
		t.Errorf("error = %v, want ErrInvalidPNG wrap", err)
	}
}

// --- Public API tests ---

func TestStripMetadata_RoutesByContentType(t *testing.T) {
	t.Parallel()
	jpegWithExif := buildJPEG([][2]any{
		{int(jpegAPP1), []byte("Exif\x00\x00payload")},
	})
	pngWithText := buildPNG([][2]any{
		{"IHDR", []byte("\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")},
		{"tEXt", []byte("Key\x00Value")},
	})

	tests := []struct {
		name        string
		ct          string
		in          []byte
		wantFormat  string
		wantChanged bool
	}{
		{"jpeg lowercase", "image/jpeg", jpegWithExif, "jpeg", true},
		{"jpeg uppercase", "IMAGE/JPEG", jpegWithExif, "jpeg", true},
		{"jpeg with charset param", "image/jpeg; charset=binary", jpegWithExif, "jpeg", true},
		{"jpg alias", "image/jpg", jpegWithExif, "jpeg", true},
		{"pjpeg alias", "image/pjpeg", jpegWithExif, "jpeg", true},
		{"png", "image/png", pngWithText, "png", true},
		{"gif passthrough", "image/gif", []byte("GIF89a anything"), "unknown", false},
		{"webp passthrough", "image/webp", []byte("RIFF anything"), "unknown", false},
		{"bmp passthrough", "image/bmp", []byte{0x42, 0x4D}, "unknown", false},
		{"empty content type", "", []byte("any bytes"), "unknown", false},
		{"malformed content type", "not;a;valid;type", []byte("any bytes"), "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := StripMetadata(tt.ct, tt.in)
			if err != nil {
				t.Fatalf("StripMetadata(%q): %v", tt.ct, err)
			}
			if res.Format != tt.wantFormat {
				t.Errorf("Format = %q, want %q", res.Format, tt.wantFormat)
			}
			if res.Changed() != tt.wantChanged {
				t.Errorf("Changed() = %v, want %v", res.Changed(), tt.wantChanged)
			}
		})
	}
}

func TestStripMetadata_ErrorsSurface(t *testing.T) {
	t.Parallel()
	// Invalid JPEG (wrong prefix) surfaces an error because the content
	// type claims jpeg and the byte parser rejects the input.
	_, err := StripMetadata("image/jpeg", []byte{0x00, 0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for malformed jpeg")
	}
	_, err = StripMetadata("image/png", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if err == nil {
		t.Fatal("expected error for malformed png")
	}
}

// TestCanonicalMediaType exercises parameter stripping and case folding.
func TestCanonicalMediaType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"image/jpeg", "image/jpeg"},
		{"IMAGE/JPEG", "image/jpeg"},
		{"image/jpeg; charset=binary", "image/jpeg"},
		{"image/jpeg;charset=binary", "image/jpeg"},
		{"  image/png  ", "image/png"},
		{"", ""},
		{"garbage;;", "garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := canonicalMediaType(tt.in)
			if got != tt.want {
				t.Errorf("canonicalMediaType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func BenchmarkStripJPEG_WithMetadata(b *testing.B) {
	input := buildJPEG([][2]any{
		{int(jpegAPP0), bytes.Repeat([]byte("JFIF"), 128)},
		{int(jpegAPP1), bytes.Repeat([]byte("EXIF"), 1024)},
		{int(jpegAPP2), bytes.Repeat([]byte("ICC_"), 2048)},
		{int(jpegAPP13), bytes.Repeat([]byte("IPTC"), 256)},
	})
	b.ResetTimer()
	for b.Loop() {
		_, _ = stripJPEG(input)
	}
}

func BenchmarkStripPNG_WithMetadata(b *testing.B) {
	input := buildPNG([][2]any{
		{"IHDR", []byte("\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")},
		{"tEXt", bytes.Repeat([]byte{'A'}, 512)},
		{"iTXt", bytes.Repeat([]byte{'B'}, 2048)},
		{"IDAT", bytes.Repeat([]byte{'C'}, 4096)},
	})
	b.ResetTimer()
	for b.Loop() {
		_, _ = stripPNG(input)
	}
}
