// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package datalabel defines the MCP receipt data-class labels derived from
// internal scanner findings.
package datalabel

import "github.com/luckyPipewrench/pipelock/internal/redact"

// DataClass is a closed, receipt-facing label synthesized from internal DLP
// classes. These labels are never parsed from agent payloads.
type DataClass string

const (
	DataClassBenign     DataClass = "benign"
	DataClassCredential DataClass = "credential"
	DataClassSecret     DataClass = "secret"
	DataClassHash       DataClass = "hash"
	DataClassNetwork    DataClass = "network"
	DataClassIdentity   DataClass = "identity"
	DataClassPII        DataClass = "pii"
)

// Valid reports whether c is one of the closed receipt data-class labels.
func (c DataClass) Valid() bool {
	switch c {
	case DataClassBenign,
		DataClassCredential,
		DataClassSecret,
		DataClassHash,
		DataClassNetwork,
		DataClassIdentity,
		DataClassPII:
		return true
	default:
		return false
	}
}

// DataClassFor maps a redaction class to its receipt data-class label.
// Unknown classes fail closed to secret because future or operator-defined
// redaction classes may represent sensitive material. The later derivation
// slice must also treat truncated or uncertain outputs as secret.
func DataClassFor(class redact.Class) DataClass {
	switch class {
	case redact.ClassAWSAccessKey,
		redact.ClassGoogleAPIKey,
		redact.ClassGitHubToken,
		redact.ClassGitLabToken,
		redact.ClassSlackToken,
		redact.ClassFireworksAPIKey,
		redact.ClassAIProviderKey,
		redact.ClassHuggingFaceToken,
		redact.ClassReplicateAPIToken,
		redact.ClassTogetherAIKey,
		redact.ClassVaultToken,
		redact.ClassVercelToken,
		redact.ClassSupabaseKey,
		redact.ClassDatabricksPAT,
		redact.ClassOpenAIAPIKey,
		redact.ClassAnthropicKey,
		redact.ClassNPMToken,
		redact.ClassPyPIToken,
		redact.ClassLinearAPIKey,
		redact.ClassNotionAPIKey,
		redact.ClassSentryAuthToken,
		redact.ClassTelegramToken,
		redact.ClassDiscordToken,
		redact.ClassTwilioAPIKey,
		redact.ClassMailgunAPIKey,
		redact.ClassSendGridAPIKey,
		redact.ClassDBConnString,
		redact.ClassAzureStorageKey,
		redact.ClassAzureSAS,
		redact.ClassJWT,
		redact.ClassBearer,
		redact.ClassCredential:
		return DataClassCredential
	case redact.ClassAWSSecretKey,
		redact.ClassSSHPrivateKey,
		redact.ClassEnvSecret,
		redact.ClassSeedPhrase,
		redact.ClassKnownSecret:
		return DataClassSecret
	case redact.ClassHashMD5,
		redact.ClassHashSHA1,
		redact.ClassHashSHA256,
		redact.ClassHashSHA512,
		redact.ClassHashNTLM:
		return DataClassHash
	case redact.ClassIPv4,
		redact.ClassIPv6,
		redact.ClassCIDR,
		redact.ClassMAC:
		return DataClassNetwork
	case redact.ClassEmail,
		redact.ClassFQDN,
		redact.ClassADUser:
		return DataClassIdentity
	case redact.ClassSSN,
		redact.ClassCreditCard:
		return DataClassPII
	default:
		return DataClassSecret
	}
}
