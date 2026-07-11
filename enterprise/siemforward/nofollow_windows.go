//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

// Windows has no os.OpenFile equivalent of O_NOFOLLOW. Lstat rejection and
// post-open regular-file verification still apply.
const noFollowFlag = 0
