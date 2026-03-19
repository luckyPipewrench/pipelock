package scanner

import (
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid test card numbers (standard test PANs).
		{name: "visa test card", input: "4111111111111111", want: true},
		{name: "mastercard test card", input: "5500000000000004", want: true},
		{name: "mastercard 2-series", input: "2223000048400011", want: true},
		{name: "amex test card", input: "378282246310005", want: true},
		{name: "discover test card", input: "6011111111111117", want: true},
		{name: "jcb test card", input: "3530111333300000", want: true},

		// Valid with separators.
		{name: "visa with dashes", input: "4111-1111-1111-1111", want: true},
		{name: "visa with spaces", input: "4111 1111 1111 1111", want: true},
		{name: "amex with spaces", input: "3782 822463 10005", want: true},

		// Invalid: bad check digit.
		{name: "visa bad check digit", input: "4111111111111112", want: false},
		{name: "mastercard bad check digit", input: "5500000000000005", want: false},
		{name: "discover bad check digit", input: "6011111111111118", want: false},

		// Invalid: wrong length.
		{name: "too short 12 digits", input: "411111111111", want: false},
		{name: "too short 14 digits", input: "41111111111118", want: false},
		{name: "too long", input: "41111111111111111111", want: false},

		// Invalid: not a card number.
		{name: "all zeros 16 digits", input: "0000000000000000", want: false}, // issuer prefix 0 is not a valid card network
		{name: "sequential", input: "1234567890123456", want: false},
		{name: "empty", input: "", want: false},
		{name: "letters", input: "abcdefghijklmnop", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateLuhn(tt.input)
			if got != tt.want {
				t.Errorf("validateLuhn(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidCardIssuer(t *testing.T) {
	tests := []struct {
		name string
		card string // digits only, no separators
		want bool
	}{
		// Visa
		{name: "visa 16", card: "4111111111111111", want: true},
		{name: "visa 19", card: "4111111111111111000", want: true},
		{name: "visa 13 retired", card: "4222222222225", want: false},
		{name: "visa wrong len 15", card: "411111111111111", want: false},

		// Mastercard 51-55
		{name: "mc 51", card: "5100000000000008", want: true},
		{name: "mc 55", card: "5500000000000004", want: true},
		{name: "mc 56 invalid", card: "5600000000000003", want: false},

		// Mastercard 2-series
		{name: "mc 2221", card: "2221000000000000", want: true},
		{name: "mc 2720", card: "2720000000000000", want: true},
		{name: "mc 2220 invalid", card: "2220000000000000", want: false},
		{name: "mc 2721 invalid", card: "2721000000000000", want: false},

		// Amex
		{name: "amex 34", card: "340000000000009", want: true},
		{name: "amex 37", card: "378282246310005", want: true},
		{name: "amex wrong len 16", card: "3400000000000090", want: false},

		// Discover
		{name: "discover 6011", card: "6011111111111117", want: true},
		{name: "discover 65", card: "6500000000000002", want: true},
		{name: "discover 644", card: "6440000000000007", want: true},
		{name: "discover 649", card: "6490000000000002", want: true},

		// JCB
		{name: "jcb 3528", card: "3528000000000007", want: true},
		{name: "jcb 3589", card: "3589000000000003", want: true},
		{name: "jcb 3527 invalid", card: "3527000000000008", want: false},

		// Invalid prefixes
		{name: "prefix 0", card: "0000000000000000", want: false},
		{name: "prefix 1", card: "1000000000000008", want: false},
		{name: "prefix 7", card: "7000000000000001", want: false},
		{name: "prefix 8", card: "8000000000000000", want: false},
		{name: "prefix 9", card: "9000000000000009", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digits := make([]byte, len(tt.card))
			for i := 0; i < len(tt.card); i++ {
				digits[i] = tt.card[i] - '0'
			}
			got := validCardIssuer(digits, len(digits))
			if got != tt.want {
				t.Errorf("validCardIssuer(%q, %d) = %v, want %v", tt.card, len(tt.card), got, tt.want)
			}
		})
	}
}

func TestValidateMod97(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid IBANs from various countries.
		{name: "UK", input: "GB29NWBK60161331926819", want: true},
		{name: "Germany", input: "DE89370400440532013000", want: true},
		{name: "France", input: "FR7630006000011234567890189", want: true},
		{name: "Spain", input: "ES9121000418450200051332", want: true},
		{name: "Mauritius with trailing letters", input: "MU17BOMM0101101030300200000MUR", want: true},
		{name: "Norway shortest IBAN 15 chars", input: "NO9386011117947", want: true},
		{name: "Honduras HN 28 chars", input: "HN53FICR12345678901234567890", want: true},
		{name: "Yemen YE 30 chars", input: "YE12CAIB1234123456789012345678", want: true},

		// Valid with spaces (formatted display).
		{name: "UK with spaces", input: "GB29 NWBK 6016 1331 9268 19", want: true},
		{name: "Germany with spaces", input: "DE89 3704 0044 0532 0130 00", want: true},

		// Valid lowercase (pipelock auto-adds (?i) to regex).
		{name: "UK lowercase", input: "gb29nwbk60161331926819", want: true},

		// Invalid: bad check digits.
		{name: "UK bad check digit", input: "GB00NWBK60161331926819", want: false},
		{name: "UK last digit changed", input: "GB29NWBK60161331926818", want: false},
		{name: "Germany zeroed check", input: "DE00370400440532013000", want: false},

		// Invalid: structural issues.
		{name: "too short", input: "GB29NWBK601613", want: false},
		{name: "too long 35 chars", input: "GB29NWBK6016133192681901234567890123", want: false},
		{name: "no country code", input: "12341234123412341234", want: false},
		{name: "empty", input: "", want: false},

		// Invalid: fake country code but passes format.
		{name: "fake country XX", input: "XX12ABCDEFGHIJK12345", want: false},
		{name: "fake country ZZ", input: "ZZ8212345678901234567890", want: false},
		{name: "DE wrong length 15 chars", input: "DE5112345678901", want: false},   // DE must be 22
		{name: "GB wrong length 18 chars", input: "GB29NWBK601613319", want: false}, // GB must be 22
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateMod97(tt.input)
			if got != tt.want {
				t.Errorf("validateMod97(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateABA(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid ABA routing numbers (real US bank routing numbers).
		{name: "JPMorgan Chase NY", input: "021000021", want: true},
		{name: "Bank of America CT", input: "011401533", want: true},
		{name: "Wells Fargo MN", input: "091000019", want: true},
		{name: "prefix 80 Federal Reserve", input: "080000004", want: true}, // prefix 80 is a valid isolated value

		// Invalid: valid prefix but bad checksum.
		{name: "prefix 01 bad checksum", input: "010000000", want: false},

		// Invalid: bad checksum.
		{name: "JPMorgan plus one", input: "021000022", want: false},
		{name: "sequential", input: "123456789", want: false},
		{name: "all nines", input: "999999999", want: false},
		{name: "all ones", input: "111111111", want: false},

		// Invalid: wrong prefix (not valid Federal Reserve district).
		{name: "prefix 99", input: "991000019", want: false},
		{name: "prefix 50", input: "501000019", want: false},
		{name: "prefix 40", input: "401000019", want: false},

		// Invalid: wrong length.
		{name: "too short", input: "02100002", want: false},
		{name: "too long", input: "0210000210", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateABA(tt.input)
			if got != tt.want {
				t.Errorf("validateABA(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDLPValidatorRegistry(t *testing.T) {
	// Verify all documented validator names are in the registry.
	for _, name := range []string{config.ValidatorLuhn, config.ValidatorMod97, config.ValidatorABA} {
		if _, ok := dlpValidators[name]; !ok {
			t.Errorf("validator %q not found in dlpValidators registry", name)
		}
	}
}

func TestCompiledPatternMatches(t *testing.T) {
	// Test that the matches() method correctly delegates to validator.
	t.Run("regex only pattern", func(t *testing.T) {
		p := &compiledPattern{
			name: "test",
			re:   mustCompileForTest(`\d{4}`),
		}
		if !p.matches("1234") {
			t.Error("expected match for regex-only pattern")
		}
		if p.matches("abcd") {
			t.Error("expected no match for non-matching text")
		}
	})

	t.Run("validated pattern accepts valid", func(t *testing.T) {
		p := &compiledPattern{
			name:     "test-luhn",
			re:       mustCompileForTest(`\d{16}`),
			validate: validateLuhn,
		}
		// 4111111111111111 passes Luhn.
		if !p.matches("4111111111111111") {
			t.Error("expected match for valid Luhn number")
		}
	})

	t.Run("validated pattern rejects invalid", func(t *testing.T) {
		p := &compiledPattern{
			name:     "test-luhn",
			re:       mustCompileForTest(`\d{16}`),
			validate: validateLuhn,
		}
		// 4111111111111112 fails Luhn.
		if p.matches("4111111111111112") {
			t.Error("expected no match for invalid Luhn number")
		}
	})

	t.Run("validated pattern finds valid after decoy", func(t *testing.T) {
		// Regression: a checksum-failing decoy before a valid card must not
		// suppress detection. matches() must check all regex hits.
		p := &compiledPattern{
			name:     "test-luhn",
			re:       mustCompileForTest(`\d{16}`),
			validate: validateLuhn,
		}
		// First 16 digits fail Luhn, second 16 digits pass.
		if !p.matches("4111111111111112 4111111111111111") {
			t.Error("expected valid card to be found after checksum-failing decoy")
		}
	})

	t.Run("validated pattern finds valid after 10+ decoys", func(t *testing.T) {
		// Regression: no fixed cap on match count. 10+ decoys must not
		// exhaust the search before the real card is checked.
		p := &compiledPattern{
			name:     "test-luhn",
			re:       mustCompileForTest(`\d{16}`),
			validate: validateLuhn,
		}
		// 11 Luhn-failing decoys followed by a valid card.
		var b strings.Builder
		for i := 0; i < 11; i++ {
			_, _ = b.WriteString("4111111111111112 ")
		}
		_, _ = b.WriteString("4111111111111111")
		if !p.matches(b.String()) {
			t.Error("expected valid card to be found after 11 checksum-failing decoys")
		}
	})
}

func mustCompileForTest(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
