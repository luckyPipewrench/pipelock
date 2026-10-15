// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardSuppressionKeepsEncodedCredentialInspection(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	secret := "sk-ant-" + "api03-" + strings.Repeat("Ab1", 20)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(secret))
	card := "4111" + "111111111111"
	supp := []config.SuppressEntry{{Rule: "Credit Card Number", Path: "*pay.vendor.example*", Reason: "test destination card policy"}}
	for _, contentType := range []string{"application/json", "text/plain"} {
		for _, prefix := range []string{"", card + " "} {
			t.Run(contentType+"/"+prefix, func(t *testing.T) {
				body := `{"note":"charge ` + prefix + `via https://api.vendor.example/` + encoded + `/x"}`
				_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(body), ContentType: contentType, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionBlock, Target: "https://pay.vendor.example/charge", Suppress: supp})
				if result.Clean || len(result.DLPMatches) == 0 {
					t.Fatalf("suppression hid credential: %+v", result)
				}
			})
		}
	}
}
