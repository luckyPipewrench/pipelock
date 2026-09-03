// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"io"
)

// resolveBestEffortOverride keeps an override's authorization together. A
// command-line override must carry its own reason and expiry; config-backed
// overrides must carry all three values in config. Falling back one field at a
// time would make the authorization's provenance ambiguous.
func resolveBestEffortOverride(
	cliEnabled bool,
	cliReason, cliExpiry string,
	cliReasonSet, cliExpirySet bool,
	configEnabled bool,
	configReason, configExpiry string,
) (enabled bool, reason, expiry string, err error) {
	if cliEnabled {
		if !cliReasonSet || !cliExpirySet {
			if configReason == "" && configExpiry == "" {
				return false, "", "", errors.New("command-line best-effort override requires both a reason and an expiry")
			}
			return false, "", "", errors.New("best-effort override cannot combine command-line and configuration values; provide its reason and expiry on the command line")
		}
		return true, cliReason, cliExpiry, nil
	}
	if configEnabled {
		if cliReasonSet || cliExpirySet {
			return false, "", "", errors.New("best-effort override cannot combine configuration and command-line values; provide its reason and expiry in configuration")
		}
		return true, configReason, configExpiry, nil
	}
	if cliReasonSet || cliExpirySet {
		return false, "", "", errors.New("best-effort reason and expiry require a best-effort override from either the command line or configuration")
	}
	return false, "", "", nil
}

func reportBestEffortAdmission(w io.Writer) {
	_, _ = fmt.Fprintln(w, "pipelock: best-effort expiry bounds launch admission only; it does not stop a running child, and every later launch requires re-authorization")
}
