// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"strings"
)

// checkViewerRFBACL requires the complete access ACL, including its base
// entries. The socket's 0660 group mode reflects the ACL mask, not group access.
func checkViewerRFBACL(ctx context.Context, run runCommand, path, proxy string, enabled bool) error {
	out, err := readAccessACL(ctx, run, path)
	if err != nil {
		return fmt.Errorf("read RFB ACL: %w", err)
	}
	want := map[string]string{"user:": "rw-", "group:": "---", "other:": "---"}
	if enabled {
		want["user:"+proxy] = "rw-"
		want["mask:"] = "rw-"
	}
	seen := make(map[string]bool, len(want))
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		var key, perms string
		switch len(parts) {
		case 2:
			key, perms = parts[0]+":", parts[1]
		case 3:
			key, perms = parts[0]+":"+parts[1], parts[2]
		default:
			return fmt.Errorf("RFB ACL unexpected entry %q", line)
		}
		expected, ok := want[key]
		if !ok {
			return fmt.Errorf("RFB ACL unexpected entry %q", key)
		}
		if seen[key] {
			return fmt.Errorf("RFB ACL duplicate entry %q", key)
		}
		seen[key] = true
		if perms != expected {
			return fmt.Errorf("RFB ACL %s is %s, want %s", key, perms, expected)
		}
	}
	for key := range want {
		if !seen[key] {
			return fmt.Errorf("RFB ACL missing entry %q", key)
		}
	}
	return nil
}
