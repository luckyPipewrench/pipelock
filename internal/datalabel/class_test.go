// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package datalabel

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestDataClassForRedactClass(t *testing.T) {
	tests := []struct {
		name string
		in   redact.Class
		want DataClass
	}{
		{"ipv4", redact.ClassIPv4, DataClassNetwork},
		{"ipv6", redact.ClassIPv6, DataClassNetwork},
		{"cidr", redact.ClassCIDR, DataClassNetwork},
		{"mac", redact.ClassMAC, DataClassNetwork},
		{"email", redact.ClassEmail, DataClassIdentity},
		{"fqdn", redact.ClassFQDN, DataClassIdentity},
		{"ad user", redact.ClassADUser, DataClassIdentity},
		{"aws access key", redact.ClassAWSAccessKey, DataClassCredential},
		{"google api key", redact.ClassGoogleAPIKey, DataClassCredential},
		{"github token", redact.ClassGitHubToken, DataClassCredential},
		{"gitlab token", redact.ClassGitLabToken, DataClassCredential},
		{"slack token", redact.ClassSlackToken, DataClassCredential},
		{"fireworks api key", redact.ClassFireworksAPIKey, DataClassCredential},
		{"ai provider key", redact.ClassAIProviderKey, DataClassCredential},
		{"huggingface token", redact.ClassHuggingFaceToken, DataClassCredential},
		{"replicate api token", redact.ClassReplicateAPIToken, DataClassCredential},
		{"together ai key", redact.ClassTogetherAIKey, DataClassCredential},
		{"vault token", redact.ClassVaultToken, DataClassCredential},
		{"vercel token", redact.ClassVercelToken, DataClassCredential},
		{"supabase key", redact.ClassSupabaseKey, DataClassCredential},
		{"databricks pat", redact.ClassDatabricksPAT, DataClassCredential},
		{"openai api key", redact.ClassOpenAIAPIKey, DataClassCredential},
		{"anthropic key", redact.ClassAnthropicKey, DataClassCredential},
		{"npm token", redact.ClassNPMToken, DataClassCredential},
		{"pypi token", redact.ClassPyPIToken, DataClassCredential},
		{"linear api key", redact.ClassLinearAPIKey, DataClassCredential},
		{"notion api key", redact.ClassNotionAPIKey, DataClassCredential},
		{"sentry auth token", redact.ClassSentryAuthToken, DataClassCredential},
		{"telegram token", redact.ClassTelegramToken, DataClassCredential},
		{"discord token", redact.ClassDiscordToken, DataClassCredential},
		{"twilio api key", redact.ClassTwilioAPIKey, DataClassCredential},
		{"mailgun api key", redact.ClassMailgunAPIKey, DataClassCredential},
		{"sendgrid api key", redact.ClassSendGridAPIKey, DataClassCredential},
		{"db connection string", redact.ClassDBConnString, DataClassCredential},
		{"azure storage key", redact.ClassAzureStorageKey, DataClassCredential},
		{"azure sas", redact.ClassAzureSAS, DataClassCredential},
		{"jwt", redact.ClassJWT, DataClassCredential},
		{"bearer", redact.ClassBearer, DataClassCredential},
		{"credential", redact.ClassCredential, DataClassCredential},
		{"aws secret key", redact.ClassAWSSecretKey, DataClassSecret},
		{"ssh private key", redact.ClassSSHPrivateKey, DataClassSecret},
		{"env secret", redact.ClassEnvSecret, DataClassSecret},
		{"seed phrase", redact.ClassSeedPhrase, DataClassSecret},
		{"known secret", redact.ClassKnownSecret, DataClassSecret},
		{"hash md5", redact.ClassHashMD5, DataClassHash},
		{"hash sha1", redact.ClassHashSHA1, DataClassHash},
		{"hash sha256", redact.ClassHashSHA256, DataClassHash},
		{"hash sha512", redact.ClassHashSHA512, DataClassHash},
		{"hash ntlm", redact.ClassHashNTLM, DataClassHash},
		{"ssn", redact.ClassSSN, DataClassPII},
		{"credit card", redact.ClassCreditCard, DataClassPII},
		{"unknown future class", redact.Class("future-sensitive-class"), DataClassSecret},
		{"empty class", redact.Class(""), DataClassSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DataClassFor(tt.in); got != tt.want {
				t.Fatalf("DataClassFor(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDataClassValid(t *testing.T) {
	for _, class := range []DataClass{
		DataClassBenign,
		DataClassCredential,
		DataClassSecret,
		DataClassHash,
		DataClassNetwork,
		DataClassIdentity,
		DataClassPII,
	} {
		t.Run(string(class), func(t *testing.T) {
			if !class.Valid() {
				t.Fatalf("%q should be valid", class)
			}
		})
	}
	t.Run("unknown label rejected", func(t *testing.T) {
		if DataClass("public").Valid() {
			t.Fatal("contract privacy data class must not be valid for MCP labels")
		}
	})
}
