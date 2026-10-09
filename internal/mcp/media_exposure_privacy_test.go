// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPMediaExposureOmitsUntrustedSubtype(t *testing.T) {
	t.Parallel()
	const secret = "private-sensitive-value-73519"
	for _, family := range []string{"image", "audio", "video"} {
		t.Run(family, func(t *testing.T) {
			cfg := config.Defaults()
			mt := family + "/" + secret
			verdict := applyMCPMediaPolicy(&cfg.MediaPolicy, mt, []byte("media payload"), "mcp")
			if !verdict.Blocked || verdict.Exposure == nil || verdict.MediaType != mt {
				t.Fatal("media enforcement changed or exposure missing")
			}
			if verdict.Exposure.ContentType != family+"/unknown" {
				t.Fatal("exposure retained untrusted subtype")
			}
			encoded, err := json.Marshal(verdict.Exposure)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), secret) || strings.Contains(verdict.BlockReason, secret) {
				t.Fatal("exposure or block reason retained untrusted subtype")
			}
			var output bytes.Buffer
			logger, err := audit.NewWithStream("json", "stdout", "", true, true, &output)
			if err != nil {
				t.Fatal(err)
			}
			logger.LogMediaExposure(audit.LogContext{}, *verdict.Exposure)
			if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), family+"/unknown") {
				t.Fatal("audit output retained subtype or lost classification")
			}
		})
	}
}
