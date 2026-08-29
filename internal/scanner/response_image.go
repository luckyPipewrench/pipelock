// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

// IsVerifiedImageResponseBody reports whether body is one complete PNG or JPEG
// with no trailing bytes. It inspects the bytes rather than trusting MIME data.
func IsVerifiedImageResponseBody(body []byte) bool {
	return isCompletePNG(body) || isCompleteJPEG(body)
}

func responseImageMetadata(body []byte) ([]byte, bool, error) {
	switch {
	case isCompletePNG(body):
		metadata, err := pngResponseMetadata(body)
		return metadata, true, err
	case isCompleteJPEG(body):
		return jpegResponseMetadata(body), true, nil
	default:
		return nil, false, nil
	}
}

func pngResponseMetadata(body []byte) ([]byte, error) {
	var metadata bytes.Buffer
	for pos := 8; pos < len(body); {
		length := int(binary.BigEndian.Uint32(body[pos : pos+4]))
		chunkType := string(body[pos+4 : pos+8])
		payload := body[pos+8 : pos+8+length]

		switch chunkType {
		case "tEXt", "eXIf":
			appendImageMetadata(&metadata, payload)
		case "zTXt":
			decoded, err := decodePNGCompressedText(payload, len(body))
			if err != nil {
				return nil, fmt.Errorf("PNG zTXt metadata: %w", err)
			}
			appendImageMetadata(&metadata, decoded)
		case "iTXt":
			decoded, err := decodePNGInternationalText(payload, len(body))
			if err != nil {
				return nil, fmt.Errorf("PNG iTXt metadata: %w", err)
			}
			appendImageMetadata(&metadata, decoded)
		}

		pos += 12 + length
	}
	return metadata.Bytes(), nil
}

func decodePNGCompressedText(payload []byte, limit int) ([]byte, error) {
	separator := bytes.IndexByte(payload, 0)
	if separator < 1 || len(payload)-separator < 3 || payload[separator+1] != 0 {
		return nil, fmt.Errorf("malformed compressed text chunk")
	}
	text, err := boundedZlibText(payload[separator+2:], limit)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, separator+1+len(text))
	result = append(result, payload[:separator]...)
	result = append(result, '\n')
	result = append(result, text...)
	return result, nil
}

func decodePNGInternationalText(payload []byte, limit int) ([]byte, error) {
	keywordEnd := bytes.IndexByte(payload, 0)
	if keywordEnd < 1 || len(payload)-keywordEnd < 5 {
		return nil, fmt.Errorf("malformed international text chunk")
	}
	rest := payload[keywordEnd+1:]
	compressionFlag := rest[0]
	compressionMethod := rest[1]
	rest = rest[2:]
	languageEnd := bytes.IndexByte(rest, 0)
	if languageEnd < 0 {
		return nil, fmt.Errorf("missing language separator")
	}
	language := rest[:languageEnd]
	rest = rest[languageEnd+1:]
	translatedEnd := bytes.IndexByte(rest, 0)
	if translatedEnd < 0 {
		return nil, fmt.Errorf("missing translated-keyword separator")
	}
	translated := rest[:translatedEnd]
	text := rest[translatedEnd+1:]

	switch compressionFlag {
	case 0:
		if compressionMethod != 0 {
			return nil, fmt.Errorf("unsupported compression method %d", compressionMethod)
		}
	case 1:
		if compressionMethod != 0 {
			return nil, fmt.Errorf("unsupported compression method %d", compressionMethod)
		}
		decoded, err := boundedZlibText(text, limit)
		if err != nil {
			return nil, err
		}
		text = decoded
	default:
		return nil, fmt.Errorf("invalid compression flag %d", compressionFlag)
	}

	var result bytes.Buffer
	appendImageMetadata(&result, payload[:keywordEnd])
	appendImageMetadata(&result, language)
	appendImageMetadata(&result, translated)
	appendImageMetadata(&result, text)
	return result.Bytes(), nil
}

func boundedZlibText(compressed []byte, limit int) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("invalid compressed text: %w", err)
	}
	defer func() { _ = reader.Close() }()

	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("reading compressed text: %w", err)
	}
	if len(decoded) > limit {
		return nil, fmt.Errorf("decompressed text exceeds image size")
	}
	return decoded, nil
}

func jpegResponseMetadata(body []byte) []byte {
	var metadata bytes.Buffer
	for pos := 2; pos < len(body); {
		for pos < len(body) && body[pos] == 0xff {
			pos++
		}
		marker := body[pos]
		pos++
		if marker >= 0xd0 && marker <= 0xd8 || marker == 0x01 {
			continue
		}
		if marker == 0xd9 {
			break
		}
		segmentLength := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		segmentEnd := pos + segmentLength
		payload := body[pos+2 : segmentEnd]
		switch marker {
		case 0xfe, 0xe1, 0xe2, 0xed:
			appendImageMetadata(&metadata, payload)
		}
		if marker == 0xda {
			break
		}
		pos = segmentEnd
	}
	return metadata.Bytes()
}

func appendImageMetadata(dst *bytes.Buffer, value []byte) {
	if len(value) == 0 {
		return
	}
	if dst.Len() > 0 {
		dst.WriteByte('\n')
	}
	_, _ = dst.Write(value)
}
