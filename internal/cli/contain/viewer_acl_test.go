// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"strings"
	"testing"
)

func TestViewerRFBACL(t *testing.T) {
	const exact = "user::rw-\nuser:proxy:rw-\ngroup::---\nmask::rw-\nother::---\n"
	for _, tc := range []struct {
		name, acl, want string
		enabled         bool
	}{
		{"exact", exact, "", true},
		{"missing", "user::rw-\ngroup::---\nmask::rw-\nother::---\n", "user:proxy", true},
		{"extra user", exact + "user:other:rw-\n", "user:other", true},
		{"extra group", exact + "group:other:rw-\n", "group:other", true},
		{"group grant", strings.Replace(exact, "group::---", "group::rw-", 1), "group:", true},
		{"wide mask", strings.Replace(exact, "mask::rw-", "mask::rwx", 1), "mask:", true},
		{"other grant", strings.Replace(exact, "other::---", "other::r--", 1), "other:", true},
		{"disabled plain", "user::rw-\ngroup::---\nother::---\n", "", false},
		{"disabled granted", exact, "user:proxy", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != "getfacl" || len(args) != 2 || args[0] != "-p" {
					t.Fatalf("unexpected ACL command: %s %v", name, args)
				}
				return tc.acl, 0, nil
			}
			err := checkViewerRFBACL(context.Background(), run, "/tmp/rfb.sock", "proxy", tc.enabled)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ACL error = %v, want %q", err, tc.want)
			}
		})
	}
}
