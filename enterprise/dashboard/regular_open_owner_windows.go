//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import "os"

// dashboardFileOwnedByCurrentUser fails closed on Windows: the Unix owner-uid
// comparison used on other platforms has no direct equivalent here, so rather
// than silently accept any owner we refuse. A real Windows ACL ownership check
// is a follow-up; until then the owner-gated dashboard stores are not served on
// Windows (mode and no-follow checks still apply on every platform).
func dashboardFileOwnedByCurrentUser(os.FileInfo) bool {
	return false
}
