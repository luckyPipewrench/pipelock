package wsutil

import "strings"

// IsExpectedCloseErr returns true for errors that are normal during connection teardown.
func IsExpectedCloseErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "EOF")
}
