// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"image/png"
	"io"
	"strings"
)

const dataImagePrefix = "data:image/"

// maxQueryEntropyImagePixels bounds the allocation made while proving that an
// image is actually decodable. png.Decode allocates the destination image sized
// to the IHDR dimensions (up to ~8 bytes per pixel) before this carve-out
// runs on the request/enforcement path, so a highly compressible IDAT could
// otherwise force a large transient allocation per candidate query value under
// concurrent scanning. Inline images in a URL query parameter are small in
// practice, so the ceiling is deliberately tight (512x512 -> ~2 MiB worst case);
// anything larger simply remains subject to the entropy gate instead of turning
// verification into a memory-exhaustion primitive.
const maxQueryEntropyImagePixels = 512 * 512

// verifiedQueryImagePlaceholder is inserted only after strict verification.
// A literal NUL cannot occur in a URL accepted by net/url, and the raw scanner
// compares this marker before percent-decoding, so external input cannot forge
// it with %00. Its high entropy makes concatenated images or surrounding data
// fail closed instead of becoming a low-entropy empty string.
const verifiedQueryImagePlaceholder = "\x00ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\x00"

// isVerifiedImageDataURL reports whether value is exactly a query-safe image
// data URL and nothing else. The query carve-out currently accepts only strict
// non-paletted PNGs; JPEG and indexed PNG fail closed because their decoders
// permit ignored non-pixel data.
func isVerifiedImageDataURL(value string) bool {
	if value == "" {
		return false
	}
	headerEnd := strings.IndexByte(value, ',')
	if headerEnd < 0 || !isExactPNGOrJPEGBase64DataImageHeader(value[:headerEnd]) {
		return false
	}
	payloadStart := headerEnd + 1
	payloadEnd := dataURLBase64PayloadEnd(value, payloadStart)
	if payloadEnd != len(value) {
		return false
	}
	decoded, ok := decodeVerifiedPNGOrJPEG(value[payloadStart:payloadEnd])
	return ok && isDecodableQueryImage(value[:headerEnd], decoded)
}

// replaceVerifiedQueryImageDataURLs is the raw-query counterpart to
// isVerifiedImageDataURL. It uses the stricter query policy while preserving
// all surrounding bytes and query separators for entropy scanning. The caller
// permits the placeholder only when it is the complete raw value.
func replaceVerifiedQueryImageDataURLs(text string) string {
	rewritten, _ := stripVerifiedImageDataURLsMatching(
		text,
		false,
		verifiedQueryImagePlaceholder,
		isExactPNGOrJPEGBase64DataImageHeader,
		isDecodableQueryImage,
	)
	return rewritten
}

// exciseVerifiedImageDataURLs removes only data:image PNG/JPEG payloads whose
// base64 bytes verify as a complete image, discarding the decoded bytes.
//
// This is the injection/response-scanning variant. A structurally valid image's
// raw bytes are not text the model interprets as instructions (multimodal
// prompt injection travels through rendered pixels, which are not scannable
// here), so dropping the decoded bytes avoids the normalization false positives
// (e.g. vowel-folded "DAN") that scanning random binary produces. Surrounding
// text remains joined so a secret split around an image does not gain a
// delimiter-based bypass.
func exciseVerifiedImageDataURLs(text string) string {
	excised, _ := stripVerifiedImageDataURLs(text, false)
	return excised
}

// exciseImagesRetainingDecodedForDLP removes the base64 *text* of verified image
// payloads (the surface that false-positives: a base64 alphabet run reads as a
// secret-shaped token) but APPENDS the decoded image bytes so a secret smuggled
// inside a structurally valid image — e.g. a literal credential in a PNG tEXt
// chunk or a JPEG comment segment — is still caught by DLP. The false positives
// come from the base64 text (a large fraction of random images contain a
// secret-shaped alphabet run); the decoded image bytes do not false-positive on
// DLP secret patterns yet still expose a literal embedded secret. This is the
// DLP (outbound exfiltration) variant: dropping the decoded bytes here would
// open a "wrap the secret in a valid image" exfiltration bypass.
func exciseImagesRetainingDecodedForDLP(text string) string {
	excised, decoded := stripVerifiedImageDataURLs(text, true)
	if len(decoded) == 0 {
		return excised
	}
	var b strings.Builder
	b.Grow(len(excised) + len(decoded) + 1)
	b.WriteString(excised)
	// A newline keeps the rejoined surrounding text and the decoded image bytes
	// as separate regions so the two cannot be spliced into one spurious token.
	b.WriteByte('\n')
	b.WriteString(decoded)
	return b.String()
}

// stripVerifiedImageDataURLs removes verified data:image PNG/JPEG base64 payloads
// from text and returns the excised text. When retainDecoded is set it also
// returns the concatenated decoded image bytes (newline-separated, one trailing
// newline per image); callers that only need the base64 text removed pass false
// to skip that allocation.
func stripVerifiedImageDataURLs(text string, retainDecoded bool) (excised, decodedConcat string) {
	return stripVerifiedImageDataURLsMatching(
		text,
		retainDecoded,
		"",
		isPNGOrJPEGBase64DataImageHeader,
		nil,
	)
}

// stripVerifiedImageDataURLsMatching scans text for data:image base64 URLs and
// removes (or replaces) only those whose header satisfies headerAllowed and
// whose decoded bytes satisfy decodedAllowed. It returns the stripped text and,
// when retainDecoded is set, the concatenation of the decoded image bytes. The
// header/decoded predicates let callers apply a stricter policy (the
// query-entropy carve-out) than the response/text-DLP excision.
func stripVerifiedImageDataURLsMatching(
	text string,
	retainDecoded bool,
	replacement string,
	headerAllowed func(string) bool,
	decodedAllowed func(string, []byte) bool,
) (excised, decodedConcat string) {
	searchFrom := 0
	copyFrom := 0
	var out strings.Builder
	var decoded strings.Builder

	for searchFrom < len(text) {
		rel := indexDataImagePrefix(text[searchFrom:])
		if rel < 0 {
			break
		}
		start := searchFrom + rel
		headerEndRel := strings.IndexByte(text[start:], ',')
		if headerEndRel < 0 {
			break
		}
		headerEnd := start + headerEndRel
		payloadStart := headerEnd + 1
		header := text[start:headerEnd]
		if !headerAllowed(header) {
			searchFrom = payloadStart
			continue
		}

		payloadEnd := dataURLBase64PayloadEnd(text, payloadStart)
		if payloadEnd <= payloadStart {
			searchFrom = payloadStart
			continue
		}
		decodedImage, ok := decodeVerifiedPNGOrJPEG(text[payloadStart:payloadEnd])
		if !ok {
			searchFrom = payloadStart
			continue
		}
		if decodedAllowed != nil && !decodedAllowed(header, decodedImage) {
			searchFrom = payloadStart
			continue
		}

		if out.Cap() == 0 {
			out.Grow(len(text))
		}
		out.WriteString(text[copyFrom:start])
		out.WriteString(replacement)
		copyFrom = payloadEnd
		searchFrom = payloadEnd
		if retainDecoded {
			decoded.Write(decodedImage)
			decoded.WriteByte('\n')
		}
	}

	if out.Cap() == 0 {
		return text, ""
	}
	out.WriteString(text[copyFrom:])
	return out.String(), decoded.String()
}

func indexDataImagePrefix(text string) int {
	if len(text) < len(dataImagePrefix) {
		return -1
	}
	for i := 0; i <= len(text)-len(dataImagePrefix); i++ {
		if asciiEqualFold(text[i:i+len(dataImagePrefix)], dataImagePrefix) {
			return i
		}
	}
	return -1
}

func asciiEqualFold(s, target string) bool {
	if len(s) != len(target) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], target[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func isPNGOrJPEGBase64DataImageHeader(header string) bool {
	parts := strings.Split(strings.ToLower(header), ";")
	if len(parts) < 2 {
		return false
	}
	switch parts[0] {
	case "data:image/png", "data:image/jpeg", "data:image/jpg":
	default:
		return false
	}
	for _, part := range parts[1:] {
		if strings.TrimSpace(part) == "base64" {
			return true
		}
	}
	return false
}

// isExactPNGOrJPEGBase64DataImageHeader reports whether header is exactly
// "data:image/png;base64" or "data:image/jpeg;base64" (case-insensitive) with
// no MIME parameters, so a secret smuggled as an extra header parameter cannot
// ride inside the header.
func isExactPNGOrJPEGBase64DataImageHeader(header string) bool {
	return asciiEqualFold(header, "data:image/png;base64") ||
		asciiEqualFold(header, "data:image/jpeg;base64")
}

// isDecodableQueryImage reports whether data is an image acceptable for the
// query-entropy carve-out: a strict true-color PNG whose every byte is
// accounted for. JPEG and indexed PNG fail closed because their decoders ignore
// metadata segments that could smuggle high-entropy data.
func isDecodableQueryImage(header string, data []byte) bool {
	switch {
	case asciiEqualFold(header, "data:image/png;base64"):
		return isStrictQueryPNG(data)
	case asciiEqualFold(header, "data:image/jpeg;base64"):
		// Go's JPEG decoder deliberately ignores APPn/COM metadata and
		// extraneous entropy-coded bytes before EOI. It does not expose the
		// byte at which pixel decoding finished, so query entropy cannot prove
		// that every accepted byte contributed to pixels. Fail closed instead
		// of giving those ignored regions an exfiltration carve-out.
		return false
	default:
		return false
	}
}

// isStrictQueryPNG accepts only IHDR/IDAT/IEND and proves that every IDAT byte
// belongs to the one zlib stream consumed by the decoder. In particular, it
// rejects ancillary/private chunks, PLTE (which is ignored for true-color PNGs),
// and the trailing-IDAT bytes that image/png intentionally ignores.
func isStrictQueryPNG(data []byte) bool {
	if !isCompletePNG(data) {
		return false
	}

	normalized := make([]byte, 0, len(data))
	normalized = append(normalized, data[:8]...)
	idatData := make([]byte, 0, len(data))
	seenIDAT := false
	for pos := 8; pos < len(data); {
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		chunkDataStart := pos + 8
		chunkDataEnd := chunkDataStart + length
		chunkEnd := chunkDataEnd + 4
		switch string(data[pos+4 : pos+8]) {
		case "IHDR":
			if seenIDAT {
				return false
			}
			normalized = append(normalized, data[pos:chunkEnd]...)
		case "IDAT":
			seenIDAT = true
			idatData = append(idatData, data[chunkDataStart:chunkDataEnd]...)
		case "IEND":
			if !seenIDAT {
				return false
			}
			normalized = appendPNGChunk(normalized, "IDAT", idatData)
			normalized = append(normalized, data[pos:chunkEnd]...)
			cfg, err := png.DecodeConfig(bytes.NewReader(normalized))
			if err != nil || !queryImageDimensionsAllowed(cfg.Width, cfg.Height) {
				return false
			}
			// Eight bytes per pixel covers PNG's widest decoded format. The
			// extra seven filter bytes per source row cover all Adam7 passes.
			maxDecoded := int64(cfg.Width)*int64(cfg.Height)*8 + int64(cfg.Height)*7
			if !isFullyConsumedZlibStream(idatData, maxDecoded) {
				return false
			}
			_, err = png.Decode(bytes.NewReader(normalized))
			return err == nil
		default:
			return false
		}
		pos = chunkEnd
	}
	return false
}

// isFullyConsumedZlibStream reports whether compressed is a single zlib stream
// that decodes within maxDecoded bytes and leaves no trailing input, so no
// hidden data can ride after the image's one consumed stream.
func isFullyConsumedZlibStream(compressed []byte, maxDecoded int64) bool {
	input := bytes.NewReader(compressed)
	decoded, err := zlib.NewReader(input)
	if err != nil {
		return false
	}
	n, copyErr := io.Copy(io.Discard, io.LimitReader(decoded, maxDecoded+1))
	closeErr := decoded.Close()
	return copyErr == nil && closeErr == nil && n <= maxDecoded && input.Len() == 0
}

// appendPNGChunk appends one PNG chunk (4-byte big-endian length, 4-byte type,
// data, 4-byte CRC-32 of type+data) to dst and returns the extended slice. It is
// used to rebuild a canonical PNG from the chunks the strict verifier accepted.
func appendPNGChunk(dst []byte, chunkType string, chunkData []byte) []byte {
	if len(chunkData) > 0xffffffff {
		return dst // chunk length must fit the PNG uint32 length field
	}
	var encoded [4]byte
	// The guard above bounds the length to the uint32 range; the mask makes the
	// conversion provably non-overflowing.
	binary.BigEndian.PutUint32(encoded[:], uint32(len(chunkData)&0xffffffff))
	dst = append(dst, encoded[:]...)
	crcStart := len(dst)
	dst = append(dst, chunkType...)
	dst = append(dst, chunkData...)
	binary.BigEndian.PutUint32(encoded[:], crc32.ChecksumIEEE(dst[crcStart:]))
	return append(dst, encoded[:]...)
}

// queryImageDimensionsAllowed reports whether a width x height image is within
// the pixel bound accepted by the query-entropy image carve-out (guards against
// a tiny header advertising an enormous decode).
func queryImageDimensionsAllowed(width, height int) bool {
	return width > 0 && height > 0 && width <= maxQueryEntropyImagePixels/height
}

func dataURLBase64PayloadEnd(text string, start int) int {
	i := start
	seenPadding := false
	padding := 0
	for i < len(text) {
		c := text[i]
		if isBase64DataURLByte(c) {
			if seenPadding {
				break
			}
			i++
			continue
		}
		if c == '=' {
			if padding >= 2 {
				break
			}
			seenPadding = true
			padding++
			i++
			continue
		}
		break
	}
	return i
}

func isBase64DataURLByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '+' || c == '/' ||
		c == '-' || c == '_'
}

// decodeVerifiedPNGOrJPEG decodes the base64 payload and returns the image bytes
// only if they parse as a complete PNG or JPEG. The returned bytes are what DLP
// re-scans so a secret embedded inside a structurally valid image is not lost.
func decodeVerifiedPNGOrJPEG(payload string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(payload)
		if err != nil || len(decoded) == 0 {
			continue
		}
		if isCompletePNG(decoded) || isCompleteJPEG(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

func isCompletePNG(data []byte) bool {
	if len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
		return false
	}
	pos := 8
	seenIHDR := false
	seenIDAT := false
	for {
		if len(data)-pos < 12 {
			return false
		}
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		if length < 0 || length > len(data)-pos-12 {
			return false
		}
		chunkTypeStart := pos + 4
		chunkDataStart := pos + 8
		chunkDataEnd := chunkDataStart + length
		crcStart := chunkDataEnd
		crcEnd := crcStart + 4

		wantCRC := binary.BigEndian.Uint32(data[crcStart:crcEnd])
		if gotCRC := crc32.ChecksumIEEE(data[chunkTypeStart:chunkDataEnd]); gotCRC != wantCRC {
			return false
		}

		chunkType := string(data[chunkTypeStart:chunkDataStart])
		switch chunkType {
		case "IHDR":
			if seenIHDR || pos != 8 || length != 13 {
				return false
			}
			seenIHDR = true
		case "IDAT":
			if !seenIHDR {
				return false
			}
			seenIDAT = true
		case "IEND":
			return seenIHDR && seenIDAT && length == 0 && crcEnd == len(data)
		}
		pos = crcEnd
	}
}

func isCompleteJPEG(data []byte) bool {
	if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 {
		return false
	}
	pos := 2
	seenSOF := false
	for pos < len(data) {
		if data[pos] != 0xff {
			return false
		}
		for pos < len(data) && data[pos] == 0xff {
			pos++
		}
		if pos >= len(data) {
			return false
		}
		marker := data[pos]
		pos++

		switch {
		case marker == 0xd9:
			return false
		case marker >= 0xd0 && marker <= 0xd7:
			continue
		case marker == 0x01 || marker == 0xd8:
			continue
		}

		if len(data)-pos < 2 {
			return false
		}
		segmentLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if segmentLength < 2 || segmentLength > len(data)-pos {
			return false
		}
		segmentEnd := pos + segmentLength
		if segmentEnd > len(data) {
			return false
		}
		if isJPEGSOFMarker(marker) {
			seenSOF = true
		}
		if marker == 0xda {
			pos = segmentEnd
			for pos < len(data) {
				if data[pos] != 0xff {
					pos++
					continue
				}
				if pos+1 >= len(data) {
					return false
				}
				next := data[pos+1]
				switch {
				case next == 0x00:
					pos += 2
				case next >= 0xd0 && next <= 0xd7:
					pos += 2
				case next == 0xd9:
					pos += 2
					return seenSOF && pos == len(data)
				default:
					return false
				}
			}
			return false
		}
		pos = segmentEnd
	}
	return false
}

func isJPEGSOFMarker(marker byte) bool {
	switch marker {
	case 0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf:
		return true
	default:
		return false
	}
}
