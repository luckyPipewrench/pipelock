package scanner

import (
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// dlpValidators maps validator names from config.DLPPattern.Validator to
// post-match validation functions. Each function receives the regex-matched
// text and returns true only if the match is a genuine financial identifier.
// This eliminates ~90-99% of regex false positives depending on the checksum.
var dlpValidators = map[string]func(string) bool{
	config.ValidatorLuhn:  validateLuhn,
	config.ValidatorMod97: validateMod97,
	config.ValidatorABA:   validateABA,
}

// validateLuhn implements the Luhn algorithm (ISO/IEC 7812) for credit card
// number validation. Strips non-digit characters (spaces, dashes) before
// checking. Returns false for strings with fewer than 13 or more than 19
// digits, or that fail the checksum. Eliminates ~90% of false positives.
func validateLuhn(s string) bool {
	// Extract digits only — cards can be space/dash separated.
	var digits [19]byte // stack-allocated, max 19 digits
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if n >= 19 {
				return false
			}
			digits[n] = s[i] - '0'
			n++
		}
	}

	if n < 13 || n > 19 {
		return false
	}

	// Luhn: from rightmost digit, double every second digit.
	// If doubling produces >9, subtract 9 (equivalent to digit-sum).
	// Valid if total sum mod 10 == 0.
	sum := 0
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i])
		if (n-i)%2 == 0 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}

	return sum%10 == 0
}

// validateMod97 implements ISO 7064 mod-97 validation for IBAN numbers.
// Uses iterative modular arithmetic — no math/big needed. Rearranges the
// IBAN (move first 4 chars to end), converts letters to numbers (A=10..Z=35),
// and checks that the result mod 97 equals 1. Eliminates ~99% of false positives.
func validateMod97(s string) bool {
	// Strip spaces and dashes, uppercase — IBANs are often formatted with
	// spaces every 4 characters (e.g. "GB29 NWBK 6016 1331 9268 19").
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return unicode.ToUpper(r)
	}, s)

	n := len(cleaned)
	if n < 15 || n > 34 {
		return false
	}

	// Must start with 2 letters (country code) + 2 digits (check digits).
	if !isASCIILetter(cleaned[0]) || !isASCIILetter(cleaned[1]) ||
		!isASCIIDigit(cleaned[2]) || !isASCIIDigit(cleaned[3]) {
		return false
	}

	// Rearrange: move first 4 characters to end.
	rearranged := cleaned[4:] + cleaned[:4]

	// Iterative mod-97: process character by character to avoid big integers.
	// Letters expand to 2 digits (A=10..Z=35), so multiply remainder by 100.
	// Digits expand to 1 digit, so multiply remainder by 10.
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		if isASCIIDigit(c) {
			remainder = (remainder*10 + int(c-'0')) % 97
		} else if isASCIILetter(c) {
			remainder = (remainder*100 + int(c-'A') + 10) % 97
		} else {
			return false // unexpected character in BBAN
		}
	}

	return remainder == 1
}

// validateABA implements the ABA routing number checksum (3-7-1 weighted sum).
// ABA routing numbers are exactly 9 digits with the weighted checksum:
// 3*d1 + 7*d2 + 1*d3 + 3*d4 + 7*d5 + 1*d6 + 3*d7 + 7*d8 + 1*d9 ≡ 0 (mod 10).
// Also validates that the first two digits fall within valid Federal Reserve
// district ranges (00-12, 21-32, 61-72, 80), reducing false positives from
// ~10% to ~4.4% of random 9-digit numbers.
func validateABA(s string) bool {
	// Extract digits only.
	var digits [9]byte
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if n >= 9 {
				return false
			}
			digits[n] = s[i] - '0'
			n++
		}
	}

	if n != 9 {
		return false
	}

	// Validate Federal Reserve district prefix (first 2 digits).
	// Valid ranges: 00-12, 21-32, 61-72, 80.
	prefix := int(digits[0])*10 + int(digits[1])
	validPrefix := (prefix <= 12) ||
		(prefix >= 21 && prefix <= 32) ||
		(prefix >= 61 && prefix <= 72) ||
		prefix == 80
	if !validPrefix {
		return false
	}

	weights := [9]int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]) * weights[i]
	}

	return sum%10 == 0
}

func isASCIILetter(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isASCIIDigit(c byte) bool  { return c >= '0' && c <= '9' }
