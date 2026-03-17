package seedprotect

import "testing"

func TestBIP39ReferenceVectors(t *testing.T) {
	vectors := []struct {
		name   string
		phrase string
		valid  bool
	}{
		// From https://github.com/trezor/python-mnemonic/blob/master/vectors.json
		{"12w: abandon x11 + about", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", true},
		{"24w: abandon x23 + art", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", true},
		{"24w: zoo x23 + wrong", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", true},
		{"12w: letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", true},
		{"12w: legal winner thank year wave sausage worth useful legal winner thank yellow", "legal winner thank year wave sausage worth useful legal winner thank yellow", true},
		{"18w: letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", true},
		{"24w: letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor bless", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor bless", true},
		// Invalid checksums
		{"invalid: abandon x12", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", false},
		{"invalid: abandon x24", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", false},
		{"invalid: zoo x12", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo", false},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			matches := Detect(v.phrase, 12, true)
			detected := len(matches) > 0

			if v.valid && !detected {
				t.Errorf("expected valid phrase to be detected (checksum should pass)")
			}
			if !v.valid && detected {
				// With verify_checksum=true, invalid checksums should not match
				t.Errorf("expected invalid checksum phrase to NOT be detected")
			}
		})
	}
}
