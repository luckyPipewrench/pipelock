// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// MediaContentType projects an upstream media type onto fixed audit labels.
// Unknown subtypes retain their media family without retaining upstream bytes.
// Enforcement must continue to classify the original type.
func MediaContentType(mt string) string {
	switch mt {
	case "image/jpeg":
		return "image/jpeg"
	case "image/jpg":
		return "image/jpg"
	case "image/pjpeg":
		return "image/pjpeg"
	case "image/png":
		return "image/png"
	case "image/gif":
		return "image/gif"
	case "image/webp":
		return "image/webp"
	case "image/bmp":
		return "image/bmp"
	case "image/x-icon":
		return "image/x-icon"
	case "image/svg+xml":
		return "image/svg+xml"
	case "audio/mpeg":
		return "audio/mpeg"
	case "audio/wav":
		return "audio/wav"
	case "audio/wave":
		return "audio/wave"
	case "audio/ogg":
		return "audio/ogg"
	case "audio/aiff":
		return "audio/aiff"
	case "audio/midi":
		return "audio/midi"
	case "audio/basic":
		return "audio/basic"
	case "video/mp4":
		return "video/mp4"
	case "video/webm":
		return "video/webm"
	case "video/avi":
		return "video/avi"
	default:
		switch {
		case strings.HasPrefix(mt, "image/"):
			return "image/unknown"
		case strings.HasPrefix(mt, "audio/"):
			return "audio/unknown"
		case strings.HasPrefix(mt, "video/"):
			return "video/unknown"
		default:
			return "unknown"
		}
	}
}
