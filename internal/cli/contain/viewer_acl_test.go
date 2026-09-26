// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestViewerRFBGroupRejectsWrongGroup(t *testing.T) {
	path := t.TempDir()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	group, ok := fileOwnerGID(info)
	if !ok {
		t.Skip("file group unavailable")
	}
	lookup := func(string) (*user.User, error) { return &user.User{Gid: strconv.FormatUint(uint64(group), 10)}, nil }
	if err := checkViewerRFBGroup(os.Stat, lookup, path); err != nil {
		t.Fatal(err)
	}
	lookup = func(string) (*user.User, error) { return &user.User{Gid: strconv.FormatUint(uint64(group)+1, 10)}, nil }
	if err := checkViewerRFBGroup(os.Stat, lookup, path); err == nil || !strings.Contains(err.Error(), "pipelock-viewer group") {
		t.Fatalf("wrong group accepted: %v", err)
	}
	if err := checkRFBGroup(os.Stat, lookup, path, "agent"); err == nil || !strings.Contains(err.Error(), "agent group") {
		t.Fatalf("disabled socket with wrong agent group accepted: %v", err)
	}
}

func TestViewerControlACLRequiresExactOperatorGrant(t *testing.T) {
	const exact = "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n"
	for _, tc := range []struct {
		name, acl string
		valid     bool
	}{
		{"exact", exact, true},
		{"missing operator", "user::rw-\ngroup::---\nmask::rw-\nother::---\n", false},
		{"wrong operator", strings.Replace(exact, "user:operator", "user:other", 1), false},
		{"extra user", exact + "user:other:rw-\n", false},
		{"group access", strings.Replace(exact, "group::---", "group::rw-", 1), false},
		{"wide mask", strings.Replace(exact, "mask::rw-", "mask::rwx", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(context.Context, string, ...string) (string, int, error) { return tc.acl, 0, nil }
			err := checkViewerControlACL(context.Background(), run, "/unused", "operator")
			if (err == nil) != tc.valid {
				t.Fatalf("ACL %q: err=%v, valid=%v", tc.name, err, tc.valid)
			}
		})
	}
}
