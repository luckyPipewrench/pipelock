// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import "strings"

// EntryLineSpace is the explicit Go unicode.IsSpace set used by evidence lines.
const EntryLineSpace = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"

// TrimEntryLine applies the recorder JSONL boundary rule to one complete line.
func TrimEntryLine(line string) string {
	return strings.Trim(line, EntryLineSpace)
}
