// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import "strings"

// DLPAtom keeps the card spelling and JSON number type alongside extracted text.
// Integers retain their original spelling but still have Number set.
type DLPAtom struct {
	Text   string
	Card   string
	Number bool
}

// JoinCardAtoms separates JSON numbers with a comma so neighboring small
// integers cannot form a card. String boundaries retain the caller's join.
func JoinCardAtoms(atoms []DLPAtom, stringSep string) string {
	var b strings.Builder
	for i, atom := range atoms {
		if i > 0 {
			if atoms[i-1].Number || atom.Number {
				b.WriteByte(',')
			} else {
				b.WriteString(stringSep)
			}
		}
		b.WriteString(atom.Card)
	}
	return b.String()
}
