// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func checkViewerRFBGroup(stat func(string) (os.FileInfo, error), lookup func(string) (*user.User, error), path string) error {
	return checkRFBGroup(stat, lookup, path, viewerUserName)
}

func checkRFBGroup(stat func(string) (os.FileInfo, error), lookup func(string) (*user.User, error), path, groupUser string) error {
	if lookup == nil {
		return fmt.Errorf("RFB group account lookup unavailable")
	}
	account, err := lookup(groupUser)
	if err != nil {
		return fmt.Errorf("RFB group account: %w", err)
	}
	want, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return fmt.Errorf("RFB group: %w", err)
	}
	info, err := stat(path)
	if err != nil {
		return fmt.Errorf("RFB socket group: %w", err)
	}
	got, ok := fileOwnerGID(info)
	if !ok || uint64(got) != want {
		return fmt.Errorf("RFB socket is not owned by the %s group", groupUser)
	}
	return nil
}

// checkViewerControlACL requires the operator grant and rejects unrelated entries.
func checkViewerControlACL(ctx context.Context, run runCommand, path, operator string) error {
	return checkExactACL(ctx, run, path, "viewer control ACL", map[string]string{"user:": "rw-", "user:" + operator: "rw-", "group:": "---", "mask:": "rw-", "other:": "---"})
}

// checkViewerControlDirACL requires that the operator can traverse the
// viewer's private runtime directory. The mask is part of the check: a
// directory chmod rewrites the mask from the mode's group bits, and a
// mask of --- silently cancels the operator's named --x entry.
func checkViewerControlDirACL(ctx context.Context, run runCommand, path, operator string) error {
	return checkExactACL(ctx, run, path, "viewer runtime directory ACL", map[string]string{"user:": "rwx", "user:" + operator: "--x", "group:": "---", "mask:": "--x", "other:": "---"})
}

// checkExactACL requires exactly the wanted access ACL entries on path.
func checkExactACL(ctx context.Context, run runCommand, path, label string, want map[string]string) error {
	out, err := readAccessACL(ctx, run, path)
	if err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	seen := make(map[string]bool, len(want))
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
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
			return fmt.Errorf("%s unexpected entry %q", label, line)
		}
		if expected, ok := want[key]; !ok || seen[key] || perms != expected {
			return fmt.Errorf("%s unexpected entry %q", label, line)
		}
		seen[key] = true
	}
	for key := range want {
		if !seen[key] {
			return fmt.Errorf("%s missing entry %q", label, key)
		}
	}
	return nil
}
