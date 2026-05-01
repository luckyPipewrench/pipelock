// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/ed25519"
	"encoding/hex"
)

const WellKnownPath = "/.well-known/http-message-signatures-directory"

type Directory struct {
	Keys []DirectoryKey `json:"keys"`
}

type DirectoryKey struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"alg"`
	PublicKey string `json:"public_key"`
	Use       string `json:"use"`
}

func (s *Signer) Directory() Directory {
	if s == nil {
		return Directory{}
	}
	pub := s.privKey.Public().(ed25519.PublicKey)
	return Directory{
		Keys: []DirectoryKey{{
			KeyID:     s.keyID,
			Algorithm: pipelockSigAlg,
			PublicKey: hex.EncodeToString(pub),
			Use:       pipelockSigTag,
		}},
	}
}
