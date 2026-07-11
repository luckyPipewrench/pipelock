//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import "os"

func dashboardFileOwnedByCurrentUser(os.FileInfo) bool {
	return true
}
