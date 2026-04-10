// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package media implements surgical metadata removal for image responses
// flowing through pipelock. The goal is pixel-identical output with EXIF,
// XMP, IPTC, and text chunks elided.
//
// This package never decodes + re-encodes images. It parses the container
// format (JPEG marker segments, PNG chunk stream) and rewrites the byte
// stream by skipping the metadata segments. That keeps latency in the
// hundreds-of-microseconds range (vs. tens of milliseconds for a full
// decode/encode round trip) and guarantees compressed pixel data is never
// touched.
//
// Supported formats:
//
//   - image/jpeg, image/jpg: strips APP1 (EXIF, XMP), APP2 (ICC profile,
//     FlashPix), APP13 (IPTC, Photoshop) segments. APP0 (JFIF header) is
//     preserved because some viewers require it.
//   - image/png: strips tEXt, iTXt, zTXt (text) and eXIf (EXIF) chunks.
//     All other chunks (IHDR, IDAT, PLTE, tRNS, IEND, etc.) pass through
//     unchanged with their original CRCs.
//
// Other image types (gif, webp, bmp) are returned unchanged. They are much
// less common metadata carriers and a future PR can add them if needed.
package media

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"strings"
)

// ErrInvalidJPEG is returned when a byte stream does not begin with a JPEG
// SOI marker or is truncated before the start-of-scan segment.
var ErrInvalidJPEG = errors.New("media: invalid or truncated JPEG")

// ErrInvalidPNG is returned when a byte stream does not begin with the PNG
// signature or a chunk length overruns the input buffer.
var ErrInvalidPNG = errors.New("media: invalid or truncated PNG")

// StripResult describes the outcome of a metadata-strip pass.
type StripResult struct {
	// Data is the rewritten image bytes. For formats where metadata was not
	// present or the format is unsupported, Data is the original input
	// (shared, not copied).
	Data []byte

	// SegmentsRemoved counts metadata segments/chunks elided from the
	// stream. Zero means no changes were made.
	SegmentsRemoved int

	// BytesRemoved is the total number of payload bytes removed. Useful for
	// metrics and the exposure event payload.
	BytesRemoved int

	// Format is the canonical format string ("jpeg", "png", or "unknown").
	Format string
}

// Changed reports whether any metadata was actually removed.
func (r *StripResult) Changed() bool { return r.SegmentsRemoved > 0 }

// StripMetadata routes a response body to the format-specific surgeon based
// on the Content-Type header. An unknown or unsupported type returns the
// input unchanged with Format="unknown" and no error — callers enforce
// allowed-type policy upstream.
//
// The media type string may include parameters (charset, boundary); they
// are parsed and ignored.
func StripMetadata(contentType string, data []byte) (*StripResult, error) {
	mt := canonicalMediaType(contentType)
	switch mt {
	case "image/jpeg", "image/jpg", "image/pjpeg":
		return stripJPEG(data)
	case "image/png":
		return stripPNG(data)
	default:
		return &StripResult{Data: data, Format: "unknown"}, nil
	}
}

// canonicalMediaType parses a Content-Type header and returns the lowercase
// media type portion with parameters stripped. Returns "" on parse error.
func canonicalMediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Fall back to a naive split on ';' to tolerate malformed headers.
		if idx := strings.IndexByte(contentType, ';'); idx >= 0 {
			return strings.ToLower(strings.TrimSpace(contentType[:idx]))
		}
		return strings.ToLower(strings.TrimSpace(contentType))
	}
	return strings.ToLower(mt)
}

// --- JPEG surgery ---

// JPEG marker byte constants. All markers begin with 0xFF, then an identifier
// byte. Standalone markers (no length field) include SOI, EOI, RSTn, and TEM.
const (
	jpegSOI  = 0xD8 // Start of Image
	jpegEOI  = 0xD9 // End of Image
	jpegSOS  = 0xDA // Start of Scan — entropy-coded data follows
	jpegAPP0 = 0xE0 // JFIF header (must preserve for JFIF files)
	jpegAPP1 = 0xE1 // EXIF, XMP
	jpegAPP2 = 0xE2 // ICC profile, FlashPix
	// jpegAPP13 carries IPTC (IIM/IPTC), Photoshop 3.0, and URL metadata
	// blocks. Stripping it removes image description, keywords, copyright,
	// author name, and location — all metadata an agent should not receive.
	jpegAPP13 = 0xED
)

// stripJPEG walks a JPEG byte stream and returns a copy with APP1, APP2, and
// APP13 segments removed. The remaining markers are emitted byte-for-byte so
// the Huffman-coded scan data is untouched.
//
// JPEG format: SOI (FFD8), then a sequence of marker segments until EOI
// (FFD9). Each segment starts with FF<marker>. Most markers carry a 2-byte
// big-endian length (inclusive of the length bytes themselves) followed by
// the segment payload. SOS is special: its header has a length, but the
// scan data that follows has no length and runs until the next FFxx marker
// that is not a restart marker (RSTn, 0xD0-0xD7) or byte-stuffing (FF00).
func stripJPEG(data []byte) (*StripResult, error) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != jpegSOI {
		return nil, ErrInvalidJPEG
	}
	result := &StripResult{Format: "jpeg"}

	// Output buffer sized to input minus a small expected savings margin.
	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	// Emit SOI.
	out.Write(data[:2])

	// Track whether we saw a Start of Scan marker AND an End of Image
	// marker. A structurally valid JPEG must contain both. An APP-only
	// input is not a renderable JPEG. A JPEG whose entropy-coded scan
	// data runs to EOF without hitting EOI is truncated. Both cases must
	// fail closed so the proxy's media-policy parse-error branch rejects
	// the response rather than forwarding a meaningless or half-written
	// stub.
	sawSOS := false
	sawEOI := false

	i := 2
	for i < len(data) {
		// Every segment starts with 0xFF. Tolerate fill bytes (repeated
		// 0xFF) between segments.
		if data[i] != 0xFF {
			return nil, fmt.Errorf("%w: expected 0xFF at offset %d, got 0x%02X", ErrInvalidJPEG, i, data[i])
		}
		j := i + 1
		for j < len(data) && data[j] == 0xFF {
			j++ // fill bytes
		}
		if j >= len(data) {
			return nil, fmt.Errorf("%w: truncated marker at offset %d", ErrInvalidJPEG, i)
		}
		marker := data[j]
		segStart := i
		segHeaderEnd := j + 1

		// Standalone markers (no length, no payload).
		if marker == jpegSOI || marker == jpegEOI || marker == 0x01 ||
			(marker >= 0xD0 && marker <= 0xD7) {
			out.Write(data[segStart:segHeaderEnd])
			i = segHeaderEnd
			if marker == jpegEOI {
				sawEOI = true
				// Reject trailing bytes after EOI. A canonical
				// JPEG ends at EOI. Accepting trailing junk
				// creates a parser-differential surface.
				if i != len(data) {
					return nil, fmt.Errorf("%w: %d trailing bytes after EOI", ErrInvalidJPEG, len(data)-i)
				}
				break
			}
			continue
		}

		// SOS: read length, emit header + scan data until next non-RST
		// non-stuffed marker. The scan data is entropy-coded; we just copy
		// bytes byte-for-byte.
		if segHeaderEnd+1 >= len(data) {
			return nil, fmt.Errorf("%w: truncated segment length at offset %d", ErrInvalidJPEG, segHeaderEnd)
		}
		segLen := int(data[segHeaderEnd])<<8 | int(data[segHeaderEnd+1])
		if segLen < 2 {
			return nil, fmt.Errorf("%w: segment length %d at offset %d below minimum 2", ErrInvalidJPEG, segLen, segHeaderEnd)
		}
		payloadEnd := segHeaderEnd + segLen
		if payloadEnd > len(data) {
			return nil, fmt.Errorf("%w: segment at offset %d overruns input (len %d)", ErrInvalidJPEG, segStart, segLen)
		}

		if marker == jpegSOS {
			sawSOS = true
			// Emit SOS header verbatim.
			out.Write(data[segStart:payloadEnd])
			// Then walk scan data until next non-stuffed non-RST marker.
			k := payloadEnd
			for k < len(data) {
				if data[k] != 0xFF {
					k++
					continue
				}
				if k+1 >= len(data) {
					// A single trailing 0xFF with no marker byte
					// after it means the entropy-coded data was
					// truncated mid-marker. Fail closed rather
					// than returning a half-written stub.
					return nil, fmt.Errorf("%w: truncated scan data: trailing 0xFF without marker byte", ErrInvalidJPEG)
				}
				next := data[k+1]
				if next == 0x00 {
					k += 2 // byte-stuffed FF00
					continue
				}
				if next >= 0xD0 && next <= 0xD7 {
					k += 2 // restart marker
					continue
				}
				// Real marker — end of scan data.
				break
			}
			out.Write(data[payloadEnd:k])
			i = k
			continue
		}

		// Strip target metadata segments.
		if isJPEGStripMarker(marker) {
			result.SegmentsRemoved++
			// BytesRemoved accounts for the full segment: 0xFF byte, fill
			// bytes, marker byte, and payload (length-inclusive).
			result.BytesRemoved += payloadEnd - segStart
			i = payloadEnd
			continue
		}

		// Keep non-stripped segment verbatim.
		out.Write(data[segStart:payloadEnd])
		i = payloadEnd
	}

	if !sawSOS {
		return nil, fmt.Errorf("%w: no SOS marker before end of stream", ErrInvalidJPEG)
	}
	if !sawEOI {
		return nil, fmt.Errorf("%w: no EOI marker before end of stream", ErrInvalidJPEG)
	}

	result.Data = out.Bytes()
	return result, nil
}

// isJPEGStripMarker reports whether a JPEG marker byte identifies a segment
// that the metadata-strip pass should remove.
func isJPEGStripMarker(marker byte) bool {
	switch marker {
	case jpegAPP1, jpegAPP2, jpegAPP13:
		return true
	}
	return false
}

// --- PNG surgery ---

// pngSignature is the fixed 8-byte prefix of every PNG file.
var pngSignature = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// pngStripChunks lists chunk types elided by the metadata strip pass.
// Values are 4-byte ASCII chunk type identifiers. Every chunk has its own
// 4-byte CRC trailer so removing a chunk is a clean byte-level operation.
var pngStripChunks = map[string]struct{}{
	"tEXt": {}, // Latin-1 text metadata
	"iTXt": {}, // International UTF-8 text metadata
	"zTXt": {}, // Compressed Latin-1 text metadata
	"eXIf": {}, // EXIF metadata container (PNG 1.5+)
}

// stripPNG walks a PNG chunk stream and returns a copy with tEXt/iTXt/zTXt
// and eXIf chunks removed. Other chunks pass through byte-for-byte with
// their original CRCs intact.
//
// PNG format: 8-byte signature, then a sequence of chunks until IEND.
// Each chunk: 4-byte length (big-endian, data bytes only), 4-byte type,
// N bytes of data, 4-byte CRC. Total per chunk: 12 + length bytes.
func stripPNG(data []byte) (*StripResult, error) {
	if len(data) < len(pngSignature) || !bytes.Equal(data[:len(pngSignature)], pngSignature) {
		return nil, ErrInvalidPNG
	}
	result := &StripResult{Format: "png"}

	out := bytes.NewBuffer(make([]byte, 0, len(data)))
	out.Write(data[:len(pngSignature)])

	// A structurally valid PNG terminates with an IEND chunk. Track
	// whether we saw one so truncated streams (signature + partial
	// chunks, no IEND) fail closed instead of returning a bogus
	// "successful" strip result that bypasses the media-policy
	// parse-error branch.
	sawIEND := false

	i := len(pngSignature)
	for i < len(data) {
		if i+8 > len(data) {
			return nil, fmt.Errorf("%w: chunk header at offset %d exceeds input length", ErrInvalidPNG, i)
		}
		chunkLen := int(data[i])<<24 | int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
		if chunkLen < 0 {
			return nil, fmt.Errorf("%w: chunk at offset %d has negative length %d", ErrInvalidPNG, i, chunkLen)
		}
		chunkType := string(data[i+4 : i+8])
		// Total chunk size: 4 length + 4 type + chunkLen data + 4 crc.
		totalLen := 12 + chunkLen
		if i+totalLen > len(data) {
			return nil, fmt.Errorf("%w: chunk %q at offset %d overruns input (len %d, remaining %d)", ErrInvalidPNG, chunkType, i, chunkLen, len(data)-i)
		}

		if _, strip := pngStripChunks[chunkType]; strip {
			result.SegmentsRemoved++
			result.BytesRemoved += totalLen
		} else {
			out.Write(data[i : i+totalLen])
		}

		i += totalLen
		if chunkType == "IEND" {
			sawIEND = true
			break
		}
	}

	if !sawIEND {
		return nil, fmt.Errorf("%w: no IEND chunk before end of stream", ErrInvalidPNG)
	}
	if i != len(data) {
		// Trailing bytes after IEND. A canonical PNG ends at IEND.
		// Accepting trailing junk creates a parser-differential surface:
		// pipelock sees a "valid" image, the agent's decoder may reject
		// or misinterpret the extra bytes. Fail closed.
		return nil, fmt.Errorf("%w: %d trailing bytes after IEND", ErrInvalidPNG, len(data)-i)
	}

	result.Data = out.Bytes()
	return result, nil
}
