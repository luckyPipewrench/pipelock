// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"

	"github.com/google/uuid"
)

// idKey authenticates identifiers minted by this process. It never leaves
// memory, so a value can only verify if NewGeneratedID produced it.
var idKey = func() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k) // crypto/rand.Read does not return an error
	return k
}()

// generatedIDMACBytes is the trailing UUID bytes that carry the proof. A
// UUIDv7 has 74 random bits; 32 carry the proof and 42 stay random, which with
// the 48-bit millisecond timestamp keeps collisions negligible.
const generatedIDMACBytes = 4

// GeneratedID is an identifier minted by this process. Its only constructor
// is NewGeneratedID; String returns a canonical UUIDv7 whose proof survives
// serialization, so the recorder boundary can establish origin from the
// value alone without trusting its spelling.
type GeneratedID struct{ s string }

// String returns the canonical UUID text, or "" for the zero value.
func (g GeneratedID) String() string { return g.s }

// NewGeneratedID mints a UUIDv7 carrying this process's origin proof. It
// returns the zero GeneratedID if the system random source fails.
func NewGeneratedID() GeneratedID {
	id, err := uuid.NewV7()
	if err != nil {
		return GeneratedID{}
	}
	b := [16]byte(id)
	mac := idMAC(b[:16-generatedIDMACBytes])
	copy(b[16-generatedIDMACBytes:], mac[:generatedIDMACBytes])
	return GeneratedID{s: uuid.UUID(b).String()}
}

// VerifyGeneratedID reports whether s is the exact canonical text of an
// identifier minted by NewGeneratedID in this process. Any other value,
// including a well-formed UUIDv7 a caller chose, is not generated.
func VerifyGeneratedID(s string) bool {
	if len(s) != 36 {
		return false
	}
	u, err := uuid.Parse(s)
	if err != nil || u.String() != s || u.Version() != 7 || u.Variant() != uuid.RFC4122 {
		return false
	}
	b := [16]byte(u)
	mac := idMAC(b[:16-generatedIDMACBytes])
	return hmac.Equal(b[16-generatedIDMACBytes:], mac[:generatedIDMACBytes])
}

func idMAC(prefix []byte) []byte {
	m := hmac.New(sha256.New, idKey)
	_, _ = m.Write(prefix)
	return m.Sum(nil)
}
