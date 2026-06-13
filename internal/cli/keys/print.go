// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// errInvalidPublicKeyLen is returned when a decoded public key is not exactly
// ed25519.PublicKeySize bytes.
var errInvalidPublicKeyLen = errors.New("invalid public key length")

// rootBannerMessage returns the readability caveat when running as root, else
// empty. Mirrors doctor's behavior so the two commands stay consistent.
func rootBannerMessage() string {
	if os.Geteuid() != 0 {
		return ""
	}
	return rootBannerText
}

// printKeyStatusReport renders the human-readable table. It writes to the
// command's configured writer (cmd.SetOut in tests) and never emits key bytes.
func printKeyStatusReport(cmd *cobra.Command, report keyStatusReport, color bool) {
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(w, "Pipelock Signing Keys")
	_, _ = fmt.Fprintln(w, "=====================")
	_, _ = fmt.Fprintf(w, "Config: %s\n", report.ConfigFile)
	if banner := rootBannerMessage(); banner != "" {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintf(w, "%s %s\n", statusTag(statusWarn, color), banner)
	}
	_, _ = fmt.Fprintln(w)
	for _, item := range report.Keys {
		_, _ = fmt.Fprintf(w, "%s %-32s [%s]\n", statusTag(item.Status, color), item.Purpose, item.SourceKind)
		_, _ = fmt.Fprintf(w, "  source:  %s\n", item.Source)
		if item.Path != "" {
			_, _ = fmt.Fprintf(w, "  path:    %s\n", item.Path)
		}
		_, _ = fmt.Fprintf(w, "  state:   present=%t readable=%t valid=%t%s\n",
			item.Present, item.Readable, item.Valid, keyTypeSuffix(item.KeyType))
		if item.Fingerprint != "" {
			_, _ = fmt.Fprintf(w, "  fingerprint: %s\n", item.Fingerprint)
		}
		if item.Note != "" {
			_, _ = fmt.Fprintf(w, "  note:    %s\n", item.Note)
		}
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Summary: %d ok, %d warning, %d info, %d failure\n",
		report.Summary.OK, report.Summary.Warn, report.Summary.Info, report.Summary.Fail)
}

// keyTypeSuffix renders " type=ed25519" when a type is known, else "".
func keyTypeSuffix(keyType string) string {
	if keyType == "" {
		return ""
	}
	return " type=" + keyType
}

// statusTag renders a colorised or plain status label.
func statusTag(status string, color bool) string {
	if !color {
		return "[" + strings.ToUpper(status) + "]"
	}
	switch status {
	case statusOK:
		return "\033[32m[OK]\033[0m"
	case statusWarn:
		return "\033[33m[WARN]\033[0m"
	case statusFail:
		return "\033[31m[FAIL]\033[0m"
	default:
		return "\033[36m[INFO]\033[0m"
	}
}
