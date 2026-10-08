// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The support bundle's configuration summary is an allowlist, so the
// acknowledgment key, its source and every acknowledgment entry stay out of
// it, including the keyed binding.
func TestRedactConfigOmitsAcknowledgments(t *testing.T) {
	const (
		key     = "synthetic-acknowledgment-key-support-01234"
		source  = "file:/run/pipelock/ack-binding.key"
		binding = "hmac-sha256-v1:0123456789abcdef:" + "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	)
	cfg := config.Defaults()
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.AcknowledgmentKey = source
	cfg.MCPToolScanning.AcknowledgmentKeyBytes = []byte(key)
	cfg.MCPToolScanning.AcknowledgedFindings = []config.MCPAcknowledgedFinding{{
		Server: "vault", ServerBindingHMAC: binding, Tool: "store_secret",
		Finding: config.MCPAckFindingRequestDirective, Owner: "platform team", Reason: "reviewed",
	}}
	enc, err := json.Marshal(redactConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{key, source, binding, "hmac-sha256-v1", "store_secret", "acknowledg"} {
		if strings.Contains(string(enc), leaked) {
			t.Errorf("support configuration summary carries %q: %s", leaked, enc)
		}
	}
}
