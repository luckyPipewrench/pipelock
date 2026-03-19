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
// number validation. Strips non-digit characters (spaces, dashes), validates
// the issuer prefix (BIN range), and checks the Luhn checksum. Returns false
// for non-card digit strings. Issuer validation is done in Go code instead of
// the regex so it's maintainable and testable without 8-file regex propagation.
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

	if n < 15 || n > 19 {
		return false
	}

	// Validate issuer prefix (BIN range). Keeps regex simple while correctly
	// covering all major card networks. New networks: add a case here.
	if !validCardIssuer(digits[:n], n) {
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

// validCardIssuer checks the first digits against known card network BIN
// ranges. This replaces complex regex alternation groups with readable Go.
func validCardIssuer(digits []byte, n int) bool {
	d0 := digits[0]

	// 4-digit prefix for range checks.
	prefix4 := int(digits[0])*1000 + int(digits[1])*100 + int(digits[2])*10 + int(digits[3])

	switch d0 {
	case 4: // Visa: starts with 4, 16/19 digits (13-digit Visa retired in the '90s)
		return n == 16 || n == 19
	case 5: // Mastercard: 51-55, 16 digits
		return digits[1] >= 1 && digits[1] <= 5 && n == 16
	case 3: // Amex (34/37): 15 digits. JCB (3528-3589): 16 digits.
		if digits[1] == 4 || digits[1] == 7 {
			return n == 15 // Amex
		}
		if prefix4 >= 3528 && prefix4 <= 3589 {
			return n == 16 // JCB
		}
		return false
	case 6: // Discover: 6011, 644-649, 65xx, 16/19 digits
		if prefix4 == 6011 || (prefix4 >= 6440 && prefix4 <= 6499) ||
			(digits[1] == 5) {
			return n == 16 || n == 19
		}
		return false
	case 2: // Mastercard 2-series: 2221-2720, 16 digits
		return prefix4 >= 2221 && prefix4 <= 2720 && n == 16
	default:
		return false
	}
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

	// Validate country code and country-specific length against the IBAN
	// registry (SWIFT/ISO 13616). Rejects fabricated country prefixes and
	// IBANs with wrong length for their country (e.g. 15-char German IBAN).
	cc := cleaned[:2]
	expectedLen, ok := ibanCountryLengths[cc]
	if !ok {
		return false
	}
	if n != expectedLen {
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

// ibanCountryLengths maps ISO 13616 IBAN country codes to their required
// total IBAN length. Rejects fabricated country prefixes and wrong-length
// IBANs (e.g. a 15-char string with DE prefix when German IBANs must be 22).
// Source: SWIFT IBAN Registry (Release 98, Dec 2024).
var ibanCountryLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
	"BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
	"BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
	"CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18,
	"FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
	"GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
	"IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
	"JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
	"LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
	"MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18,
	"NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29,
	"PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
	"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19,
	"SK": 24, "SM": 27, "SN": 28, "SO": 23, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
	"VA": 22, "VG": 24, "XK": 20,
}
