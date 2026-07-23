// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	contentTypeJSON = "application/json"
	contentTypeCEF  = "text/plain; charset=utf-8"
)

// formatEvent renders every configured export surface through one dispatch
// path. FormatOCSFEvent and FormatCEFEvent remain the single encoders for their
// respective wire formats; sinks only select the transport and content type.
func formatEvent(event Event, format, deviceVersion string) ([]byte, string, error) {
	if format == "" {
		format = FormatJSON
	}

	switch format {
	case FormatCEF:
		return []byte(FormatCEFEvent(event, deviceVersion)), contentTypeCEF, nil
	case FormatOCSF:
		return []byte(FormatOCSFEvent(event, deviceVersion)), contentTypeJSON, nil
	case FormatJSON:
		payload := webhookPayload{
			Severity:  event.Severity.String(),
			Type:      event.Type,
			Timestamp: event.Timestamp.UTC().Format(time.RFC3339Nano),
			Instance:  event.InstanceID,
			Fields:    event.Fields,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, "", err
		}
		return body, contentTypeJSON, nil
	default:
		return nil, "", fmt.Errorf("emit: unsupported event format %q", format)
	}
}
