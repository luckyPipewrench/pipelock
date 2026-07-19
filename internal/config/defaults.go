// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// CredentialSolicitationRegex is the canonical direction-anchored response
// pattern for requests that try to make the agent hand credentials back to the
// requester. The immutable scanner floor and default config both use this
// value; preset YAML files are guarded by a parity test.
const CredentialSolicitationRegex = `(?i)(\b(?:send|provide|paste|return|supply|submit|share|hand|give|forward|transmit|reveal|disclose|include|leak|expose|dump|email|upload|post)\b(?:[^.!?]|\.\S){0,40}?\b(?:password|passwd|token|api[_ -]?key|secret|credentials?|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b(?:[^\n.!?]|\.\S){0,40}?(?:to\s+(?:verify|confirm|authenticate|validate|continue|proceed|complete)|so\s+(?:that\s+)?(?:i|we)\s+can|for\s+(?:this|the)\s+(?:request|operation|transaction|session|verification|authentication|step|action|call|task)|in\s+(?:your|the)\s+(?:reply|response|message|answer|chat)|(?:back\s+)?to\s+(?:me|us)\b|with\s+(?:me|us)\b|to\s+this\s+(?:chat|thread|conversation|agent|assistant)|to\s+the\s+(?:following|url|link|endpoint|address|server)|to\s+https?://|to\s+\S+@\S+)|\b(?:send|provide|paste|return|supply|submit|share|hand|give|forward|transmit|reveal|disclose|include|leak|expose|dump|email|upload|post)\b(?:[^\n.!?]|\.\S){0,30}?(?:to\s+(?:verify|confirm|authenticate|validate|continue|proceed|complete)|so\s+(?:that\s+)?(?:i|we)\s+can|for\s+(?:this|the)\s+(?:request|operation|transaction|session|verification|authentication|step|action|call|task)|in\s+(?:your|the)\s+(?:reply|response|message|answer|chat)|(?:back\s+)?to\s+(?:me|us)\b|with\s+(?:me|us)\b|to\s+this\s+(?:chat|thread|conversation|agent|assistant)|to\s+the\s+(?:following|url|link|endpoint|address|server)|to\s+https?://|to\s+\S+@\S+)(?:[^\n.!?]|\.\S){0,30}?\b(?:password|passwd|token|api[_ -]?key|secret|credentials?|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b)` // #nosec G101 -- detection regex: contains credential nouns to MATCH solicitation text, not a hardcoded credential

// AWSAccessIDRegex is the canonical AWS access-key/user/role/policy ID shape
// used by both default config DLP and the immutable core scanner floor.
const AWSAccessIDRegex = `(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`

const (
	markdownLinkCredentialExfilVerbAlt = `send|upload|post|submit|paste|append|put|exfiltrat\w*|leak`
	markdownLinkCredentialExfilNounAlt = `a[\s_-]*p[\s_-]*i[\s_-]*keys?|t[\s_-]*o[\s_-]*k[\s_-]*e[\s_-]*n[\s_-]*s?|s[\s_-]*e[\s_-]*c[\s_-]*r[\s_-]*e[\s_-]*t[\s_-]*s?|c[\s_-]*r[\s_-]*e[\s_-]*d[\s_-]*e[\s_-]*n[\s_-]*t[\s_-]*i[\s_-]*a[\s_-]*l[\s_-]*s?|p[\s_-]*a[\s_-]*s[\s_-]*s[\s_-]*w[\s_-]*o[\s_-]*r[\s_-]*d[\s_-]*s?|s[\s_-]*e[\s_-]*s[\s_-]*s[\s_-]*i[\s_-]*o[\s_-]*n[\s_-]*s[\s_-]*e[\s_-]*c[\s_-]*r[\s_-]*e[\s_-]*t[\s_-]*s?` // #nosec G101 -- detection regex fragment: credential nouns to MATCH exfiltration instructions, not a hardcoded credential
	markdownLinkCredentialExfilLink    = `\[[^\n]{1,160}\]\(\s*https?://[^)\s]+|<\s*https?://[^>\s]+>|\[[^\n]{1,160}\]\s*\[[^\]\n]{1,80}\](?:[^\n]|\n[ \t]*){0,240}\[[^\]\n]{1,80}\]:\s*https?://[^\s]+`                                                                                                                                                                                                                                // #nosec G101 -- detection regex fragment, not a hardcoded credential
	markdownLinkCredentialDestination  = `(?:the\s+following\s+|(?:(?:this|that|our|my|their|a|an|the)\s+)?(?:(?:secure|external|collection|upload|remote)\s+)*(?:link|url|endpoint|server|form|page|address)\b\s*[:,-]?\s*)?`
	markdownLinkCredentialTerminalCue  = `(?:\s*(?:[.!?]|$)|\s+(?:here|there)\b)` // #nosec G101 -- detection regex fragment, not a hardcoded credential
	markdownLinkVerbNounGap            = `(?:[^\n.!?]|\.\S){0,80}`
	// markdownLinkCredentialTransmitObjectAlt anchors the "collect/copy/include
	// NOUN, then VERB ... link" branch so the transfer verb must act on the
	// credential itself (a pronoun referring back to it, or the credential noun
	// restated) rather than on some unrelated object introduced later in the
	// same sentence (e.g. "copy your token, then send us a message via [link]",
	// where "send" governs "a message", not the token).
	markdownLinkCredentialTransmitObjectAlt = `it|them|that|those|these`

	// MarkdownLinkCredentialValueExfilRegex covers the narrow antecedent form
	// "copy/include/collect credential, then submit the value to [link]".
	// Keeping it separate from MarkdownLinkCredentialExfilRegex preserves the
	// preset YAML regex byte-for-byte while restoring core/default coverage for
	// a real exfiltration object that the tightened object anchor no longer
	// accepts. It intentionally only adds values? as the anaphoric object; broad
	// nouns like "message" remain clean false-positive fixes.
	MarkdownLinkCredentialValueExfilRegex = `(?is)\b(?:collect|copy|include)\b(?:[^\n.!?]|\.\S){0,80}\b(?:` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,120}\b(?:` + markdownLinkCredentialExfilVerbAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:the\s+)?values?\b(?:[^\n.!?]|\.\S){0,80}\b(?:to|into|onto|in|at|via|using|through|here|there)\b\s*` + markdownLinkCredentialDestination + `(?:` + markdownLinkCredentialExfilLink + `)` // #nosec G101 -- detection regex: contains credential nouns to MATCH exfiltration instructions, not a hardcoded credential

	// markdownLinkCredentialCollectVerbAlt anchors the collection half of
	// MarkdownLinkCredentialFollowExfilRegex: an instruction to gather up a
	// credential, distinct from the transmit verbs above.
	markdownLinkCredentialCollectVerbAlt = `collect|gather|grab|copy`
	// markdownLinkCredentialFollowCollectedMaterial keeps the indirect
	// follow-link pattern scoped to suspicious collection phrases: sweeping
	// "any/all" credential collection, credentials from this session, or
	// session secrets. Plain setup docs usually say "your API token from the
	// console" or "the recovery token", which stays outside this fragment.
	markdownLinkCredentialFollowCollectedMaterial = `(?:(?:any|all)\b(?:[^\n.!?]|\.\S){0,40}\b(?:` + markdownLinkCredentialExfilNounAlt + `)|(?:` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\bfrom\s+this\s+session|s[\s_-]*e[\s_-]*s[\s_-]*s[\s_-]*i[\s_-]*o[\s_-]*n[\s_-]*s[\s_-]*e[\s_-]*c[\s_-]*r[\s_-]*e[\s_-]*t[\s_-]*s?)`
	// markdownLinkCredentialFollowVerbAlt anchors the second, INDIRECT half:
	// an instruction to open/follow a link rather than to transmit the
	// credential to it. The credential is never named as the object of this
	// verb - the link itself is the exfiltration channel.
	markdownLinkCredentialFollowVerbAlt = `open|follow|visit|go\s+to|navigate\s+to`
	// markdownLinkCredentialFollowCueAlt requires the link-follow to be
	// framed as an objectless hand-over cue (sync/upload/send), not an
	// ordinary setup/doc noun phrase like "continue setup" or "sync your
	// devices". "continue" is deliberately not a cue here: benign setup docs
	// naturally say "open this link to continue: [finish setup](...)".
	markdownLinkCredentialFollowCueAlt = `sync|upload|send`

	// MarkdownLinkCredentialFollowExfilRegex detects an INDIRECT markdown-link
	// exfiltration shape that MarkdownLinkCredentialExfilRegex above does not
	// cover: the credential is never the object of a transmit verb (send,
	// upload, submit, ...) at all. Instead the response separately instructs
	// the reader to (1) collect/gather/grab/copy scoped credential material
	// ("any/all" credentials, credentials from this session, or session
	// secrets), then (2) open/follow/visit/go-to/navigate-to a link, with
	// the link-follow framed as a sync/upload/send hand-over. The link itself
	// is the exfiltration channel (for example the collected value riding in
	// a query parameter), so no "send it to the link" phrasing is required.
	//
	// The literal "link" noun anchor after the follow verb is what keeps
	// this narrow: ordinary setup docs name what they are opening ("open
	// the docs", "open the setup guide", "open the dashboard"), they do not
	// say "open this link" bare, and requiring a sync/upload/send
	// cue further ensures the link-follow reads as completing a hand-over
	// rather than reading more documentation. The cue must be the whole
	// phrase before the markdown link ("to sync: [continue](...)"), not a
	// benign object phrase ("to sync your devices") or generic onboarding
	// language ("to continue: [finish setup](...)"). Benign prose like
	// "gather the API keys you need from the console, then open the docs
	// [...](...) for setup" or "copy the token into your .env, then open the
	// guide [...](...)" stays clean because neither names "link" as the
	// object of the follow verb. Every gap uses the same clause-aware
	// character class ([^\n.!?] or \.\S for abbreviations) as the sibling
	// markdown-link patterns above, so a two-clause sentence split by a
	// period does not bridge into a false match.
	// Deliberately has NO redaction-class mirror: like
	// MarkdownLinkCredentialExfilRegex above, this matches a whole
	// collect-then-follow instruction, not a bare credential-secret shape.
	MarkdownLinkCredentialFollowExfilRegex = `(?is)\b(?:` + markdownLinkCredentialCollectVerbAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:` + markdownLinkCredentialFollowCollectedMaterial + `)\b(?:[^\n.!?]|\.\S){0,120}\b(?:` + markdownLinkCredentialFollowVerbAlt + `)\b(?:[^\n.!?]|\.\S){0,15}?\b(?:link|url|address)\b(?:[^\n.!?]|\.\S){0,20}?\bto\s+(?:` + markdownLinkCredentialFollowCueAlt + `)\b\s*[:,-]?\s*(?:` + markdownLinkCredentialExfilLink + `)` // #nosec G101 -- detection regex: contains credential nouns to MATCH exfiltration instructions, not a hardcoded credential

	// MarkdownLinkCredentialExfilRegex detects injected instructions that pair
	// credential transfer with an exfiltration-destination cue anchored directly
	// to an external markdown, angle, or reference-style link. The branches cover:
	// transfer verb + credential noun + destination cue before the link, collection
	// phrasing that later names a transfer verb and destination cue, link-first
	// "to VERB credential" phrasing, and link-first "VERB credential here/there"
	// phrasing. The terminal cue on the "to VERB" branch avoids matching setup
	// docs that use a link and then tell the reader to paste a token into a local
	// app. Credential nouns allow whitespace, underscore, and hyphen spacing
	// between letters so normalized evasions still match; destination terms stay
	// narrow so ordinary setup docs with benign links do not block.
	// Every verb<->noun gap uses either a short clause-aware gap or a
	// comma-set-off parenthetical gap, never a bare DOTALL '.', so the transfer
	// verb and the credential noun must co-occur in the SAME clause without
	// crossing coordinated objects: a benign two-clause sentence like
	// "Please send your invoice and include your account token in the email to
	// [billing]" no longer matches, because "send" and "token" sit in different
	// coordinated objects split by "and include". A same-clause parenthetical
	// like "send, after copying it exactly, the API key to [link]" still blocks.
	// The "collect/copy/include NOUN, then VERB ... link" branch additionally
	// requires the verb's object to be the credential itself
	// (markdownLinkCredentialTransmitObjectAlt) so a second, unrelated action in
	// the same sentence ("copy your token, then send us a message via [link]")
	// does not match on the verb alone.
	// Scanner response matching depends on the invariant that this regex can only
	// match content containing a literal http:// or https:// link; broaden URL
	// schemes only with matching updates to responsePatternRequiredLiterals and
	// TestMarkdownLinkCredentialExfilRegexRequiresHTTPURL.
	// Deliberately has NO redaction-class mirror in internal/redact/classes.go.
	// Redaction classes match a bare credential-secret SHAPE (a token/key value)
	// so that shape can be placeholder-substituted on an allowlisted host. This
	// pattern instead matches a whole exfiltration-instruction SENTENCE (a
	// transfer verb, a credential noun, and a destination link, in varying
	// order) with no single "secret value" span to redact — the match can
	// include prose and a full markdown link, not a credential value. Every
	// other response-scanning injection pattern in this file (Credential
	// Solicitation, Credential Path Directive, Prompt Injection, etc.) is the
	// same shape and likewise has no redaction mirror; only DLP/secret-value
	// patterns (AWS keys, GitHub tokens, connection strings, ...) do. This
	// pattern is block-only by design, not by omission.
	MarkdownLinkCredentialExfilRegex = `(?is)(?:(?:\b(?:` + markdownLinkCredentialExfilVerbAlt + `)\b` + markdownLinkVerbNounGap + `\b(?:` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:to|into|onto|in|at|via|using|through|here|there)\b\s*` + markdownLinkCredentialDestination + `|\b(?:collect|copy|include)\b(?:[^\n.!?]|\.\S){0,80}\b(?:` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,120}\b(?:` + markdownLinkCredentialExfilVerbAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:` + markdownLinkCredentialTransmitObjectAlt + `|` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:to|into|onto|in|at|via|using|through|here|there)\b\s*` + markdownLinkCredentialDestination + `)(?:` + markdownLinkCredentialExfilLink + `)|(?:` + markdownLinkCredentialExfilLink + `)(?:[^\n.!?]|\.\S){0,80}\bto\s+(?:` + markdownLinkCredentialExfilVerbAlt + `)\b` + markdownLinkVerbNounGap + `\b(?:` + markdownLinkCredentialExfilNounAlt + `)\b` + markdownLinkCredentialTerminalCue + `|(?:` + markdownLinkCredentialExfilLink + `)(?:[^\n.!?]|\.\S){0,120}\b(?:` + markdownLinkCredentialExfilVerbAlt + `)\b` + markdownLinkVerbNounGap + `\b(?:` + markdownLinkCredentialExfilNounAlt + `)\b(?:[^\n.!?]|\.\S){0,80}\b(?:here|there)\b)` // #nosec G101 -- detection regex: contains credential nouns to MATCH exfiltration instructions, not a hardcoded credential
)

const (
	// authMaterialRequirementHandoverAlt is the direction-cue alternation that
	// anchors AuthMaterialRequirementRegex to an actual hand-over request,
	// mirroring the direction cues in CredentialSolicitationRegex. A bare
	// "an API key is required" statement (ordinary setup/auth documentation)
	// does not match on its own; the pattern additionally requires a
	// solicitation verb aimed at the reader/agent handing the credential back
	// (to the requester, in a reply, to a URL or email, etc.) in the same
	// clause as the requirement statement.
	authMaterialRequirementHandoverVerbAlt = `provide|enter|paste|type|submit|include|share|supply|send|give|hand|reply\s+with|respond\s+with`
	authMaterialRequirementBareVerbAlt     = `provide|paste|submit|include|share|supply|send|give|hand|reply\s+with|respond\s+with`
	authMaterialRequirementHandoverAlt     = `to\s+(?:verify|confirm|authenticate|validate|continue|proceed|complete)|so\s+(?:that\s+)?(?:i|we)\s+can|for\s+(?:this|the)\s+(?:request|operation|transaction|session|verification|authentication|step|action|call|task)|in\s+(?:your|the)\s+(?:reply|response|message|answer|chat)|(?:back\s+)?to\s+(?:me|us)\b|with\s+(?:me|us)\b|to\s+this\s+(?:chat|thread|conversation|agent|assistant)|to\s+the\s+(?:following|url|link|endpoint|address|server)|to\s+https?://|to\s+\S+@\S+|(?:here|there)\b`
	authMaterialRequirementStatement       = `\bto\s+(complete|continue|finish|proceed|verify)\b(?:[^.!?]|\.\S){0,40}\b(authentication|credential|token|api[_ -]?key|private[_ -]?key|ssh[_ -]?key)\b(?:[^.!?]|\.\S){0,40}\b(required|needed|necessary|must be)\b`
	authMaterialRequirementPronounAlt      = `it|them|that|this|those|these`
	authMaterialRequirementPronounDirected = `\b(?:` + authMaterialRequirementPronounAlt + `)\b(?:[^.!?]|\.\S){0,40}?(?:` + authMaterialRequirementHandoverAlt + `)`
	authMaterialRequirementPronounTerminal = `\b(?:` + authMaterialRequirementPronounAlt + `)\b\s*(?:[.!?]|$)`

	// AuthMaterialRequirementRegex detects a stated credential requirement
	// ("to complete/continue/finish/proceed/verify ... a credential is
	// required/needed/necessary") ONLY when it is paired, in the same clause,
	// with an explicit request that the reader/agent hand the credential back
	// to the requester (authMaterialRequirementHandoverVerbAlt +
	// authMaterialRequirementHandoverAlt). Ordinary documentation that merely
	// states a precondition ("To complete registration, a valid API key is
	// required. See the setup guide...") has no hand-over cue and stays clean.
	// Every gap uses a clause-aware character class ([^.!?] or \.\S), never a
	// bare DOTALL '.', so a requirement stated in one sentence and an
	// unrelated later sentence cannot be bridged into a false match; newlines
	// are still allowed to cross so a payload split across lines is caught.
	// Deliberately has NO redaction-class mirror: like
	// MarkdownLinkCredentialExfilRegex above, this matches a whole
	// requirement-plus-handover SENTENCE, not a bare credential-secret shape,
	// so there is no single value to placeholder-substitute. Block-only by
	// design; see the redaction-mirror note on MarkdownLinkCredentialExfilRegex.
	AuthMaterialRequirementRegex = `(?is)(?:` + authMaterialRequirementStatement + `(?:[^.!?]|\.\S){0,60}?\b(?:` + authMaterialRequirementHandoverVerbAlt + `)\b(?:[^.!?]|\.\S){0,40}?(?:` + authMaterialRequirementHandoverAlt + `)|` + authMaterialRequirementStatement + `(?:[^.!?]|\.\S){0,60}?\b(?:` + authMaterialRequirementHandoverVerbAlt + `)\b(?:[^.!?]|\.\S){0,20}?(?:` + authMaterialRequirementPronounDirected + `|` + authMaterialRequirementPronounTerminal + `)|` + authMaterialRequirementStatement + `\s*(?:[.!?]|\n)\s*\b(?:` + authMaterialRequirementHandoverVerbAlt + `)\b(?:[^.!?]|\.\S){0,20}?(?:` + authMaterialRequirementPronounDirected + `|` + authMaterialRequirementPronounTerminal + `)|` + authMaterialRequirementStatement + `\s*(?:[.!?]|\n)\s*\b(?:` + authMaterialRequirementBareVerbAlt + `)\b(?:[^.!?]|\.\S){0,20}?(?:` + authMaterialRequirementHandoverAlt + `))` // #nosec G101 -- detection regex: contains credential nouns to MATCH a requirement+handover statement, not a hardcoded credential
)

const (
	credentialPathTerminalCue = `(?:\s*(?:$|[\r\n!?;,|&<>])|\.(?:\s|$)|\s+(?:file|contents?)\b)` // #nosec G101 -- detection regex fragment, not a hardcoded credential
	credentialPathSSHKey      = `(?:~?[/\\]?\.ssh[/\\](?:id_rsa|id_ed25519)|\b(?:id_rsa|id_ed25519))` + credentialPathTerminalCue
	credentialPathAWSCreds    = `\.aws[/\\]credentials` + credentialPathTerminalCue

	credentialPathHighSignalWithPasswd = `(?:` + credentialPathSSHKey + `|` + credentialPathAWSCreds + `|/etc/passwd\b|/etc/shadow\b)`
	credentialPathHighSignalShadowOnly = `(?:` + credentialPathSSHKey + `|` + credentialPathAWSCreds + `|/etc/shadow\b)`

	// CredentialPathDirectiveRegex detects instructions that access sensitive
	// credential paths. High-signal paths block on strong bare access verbs; the
	// broader verb/path set still requires a same-clause output or exfiltration
	// cue so setup docs that only mention doc-prone paths do not match. The
	// bare read branch intentionally keeps /etc/shadow but omits /etc/passwd so
	// "read the /etc/passwd format in the docs" stays clean.
	CredentialPathDirectiveRegex = `(?is)(?:` +
		`\b(?:cat|less|more|head|tail|base64|xxd|fetch|retrieve|extract)\b(?:[^.!?]|\.\S){0,80}` + credentialPathHighSignalWithPasswd +
		`|\bread\b(?:[^.!?]|\.\S){0,80}` + credentialPathHighSignalShadowOnly +
		`|\bdd\b(?:[^.!?]|\.\S){0,40}\bif\s*=\s*(?:file://)?` + credentialPathHighSignalWithPasswd +
		`|\bcurl\b(?:[^.!?]|\.\S){0,80}\bfile://` + credentialPathHighSignalWithPasswd +
		`|\bopenssl\b(?:[^.!?]|\.\S){0,80}(?:^|\s)-in\s+(?:file://)?` + credentialPathHighSignalWithPasswd +
		`|\b(?:read|get|fetch|retrieve|cat|copy|extract|open|include)\b(?:[^.!?]|\.\S){0,80}(?:\.ssh[/\\]|\.aws[/\\]credentials|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\bkubeconfig\b|/etc/passwd\b|/etc/shadow\b)(?:[^.!?]|\.\S){0,160}(?:\b(?:send|forward|transmit|share|email|exfiltrat\w*|leak)\b(?:[^.!?]|\.\S){0,60}?(?:(?:back\s+)?to\s+(?:me|us)\b|with\s+(?:me|us)\b|in\s+(?:your|the)\s+(?:reply|response|message|answer|chat|request)|(?:to|into|onto|via|using|through)\s+https?://|to\s+\S+@\S+|\b(?:it|them|contents?|file|data|key|keys?|values?|secrets?)\b)|\b(?:paste|return|report|dump|print|output|display|show|upload|post|submit)\b(?:[^.!?]|\.\S){0,60}?(?:\b(?:it|them|contents?|file|data|key|keys?|values?|secrets?)\b|(?:to|into|onto|via|using|through)\s+https?://|to\s+\S+@\S+)|\bcurl\b(?:[^.!?]|\.\S){0,80}?(?:\b(?:it|them|contents?|file|data|key|keys?|values?|secrets?)\b(?:[^.!?]|\.\S){0,40}?\bto\s+\S+\.\S+|https?://|\S+\.\S+)|\|\s*(?:openssl\s+base64|base64|xxd)\b|\bin\s+(?:your|the)\s+(?:reply|response|message|answer|chat|request)\b))` // #nosec G101 -- detection regex: contains credential path names to MATCH path-exfiltration instructions, not a hardcoded credential
)

type providerKeyDomainDefault struct {
	rule   string
	domain string
}

var defaultProviderKeyDomains = []providerKeyDomainDefault{
	{rule: "Anthropic API Key", domain: "*.anthropic.com"},
	{rule: "OpenAI API Key", domain: "*.openai.com"},
	{rule: "OpenAI Service Key", domain: "*.openai.com"},
	{rule: "Fireworks API Key", domain: "*.fireworks.ai"},
	{rule: "LLM Router API Key", domain: "*.openrouter.ai"},
	{rule: "Answer Engine API Key", domain: "*.perplexity.ai"},
	{rule: "Web Research API Key", domain: "*.tavily.com"},
	{rule: "Google API Key", domain: "*.googleapis.com"},
	{rule: "Hugging Face Token", domain: "*.huggingface.co"},
	{rule: "Databricks Token", domain: "*.databricks.com"},
	{rule: "Replicate API Token", domain: "*.replicate.com"},
	{rule: "Together AI Key", domain: "*.together.ai"},
	{rule: "Pinecone API Key", domain: "*.pinecone.io"},
	{rule: "Groq API Key", domain: "*.groq.com"},
	{rule: "xAI API Key", domain: "*.x.ai"},
}

func providerKeyExemptDomains(rule string) []string {
	for _, d := range defaultProviderKeyDomains {
		if d.rule == rule {
			return []string{d.domain}
		}
	}
	return nil
}

func defaultProviderKeySuppressions() []SuppressEntry {
	out := make([]SuppressEntry, 0, len(defaultProviderKeyDomains))
	for _, d := range defaultProviderKeyDomains {
		out = append(out, SuppressEntry{
			Rule:   d.rule,
			Path:   d.domain + "*",
			Reason: "provider-bound credential",
		})
	}
	return out
}

// Defaults returns a Config with sensible defaults for balanced mode.
func Defaults() *Config {
	cfg := &Config{
		Version:                    1,
		Mode:                       ModeBalanced,
		canonicalHashCache:         &canonicalHashCacheHolder{},
		canonicalRedactionKeyCache: &canonicalHashCacheHolder{},
		// CRL freshness window default (consulted only under require-intermediate
		// mode). The license_crl_max_age knob and EnvLicenseCRLMaxAge override it;
		// a missing/non-positive value clamps back to this default in Load and at
		// the verify boundary, so a misconfiguration never disables the check.
		LicenseCRLMaxAgeResolved: license.DefaultCRLMaxAge,
		APIAllowlist: []string{
			"*.anthropic.com",
			"*.openai.com",
			"github.com",
			"*.github.com",
			"*.githubusercontent.com",
			"registry.npmjs.org",
		},
		FetchProxy: FetchProxy{
			Listen:         DefaultListen,
			TimeoutSeconds: 30,
			MaxResponseMB:  10,
			UserAgent:      "Pipelock Fetch/1.0",
			Monitoring: Monitoring{
				MaxURLLength:              2048,
				EntropyThreshold:          4.5,
				SubdomainEntropyThreshold: 4.0,
				MaxReqPerMinute:           60,
				Blocklist: []string{
					"*.pastebin.com",
					"*.hastebin.com",
					"*.paste.ee",
					"*.transfer.sh",
					"*.file.io",
					"*.requestbin.com",
				},
				SubdomainEntropyExclusions: []string{
					"files.pythonhosted.org",
					"pypi.org",
					"objects.githubusercontent.com",
				},
			},
		},
		ForwardProxy: ForwardProxy{
			Enabled:            false,
			MaxTunnelSeconds:   300,
			IdleTimeoutSeconds: 120,
			SNIVerification:    ptrBool(true),
		},
		WebSocketProxy: WebSocketProxy{
			Enabled:                  false,
			MaxMessageBytes:          1048576,
			MaxConcurrentConnections: 128,
			ScanTextFrames:           ptrBool(true),
			StripCompression:         ptrBool(true),
			MaxConnectionSeconds:     3600,
			IdleTimeoutSeconds:       300,
			OriginPolicy:             OriginPolicyRewrite,
		},
		RequestPolicy: RequestPolicy{
			OnParseError:      ActionBlock,
			OnOpaqueOperation: ActionBlock,
		},
		Suppress: defaultProviderKeySuppressions(),
		DLP: DLP{
			ScanEnv:  true,
			Patterns: DefaultDLPPatterns(),
		},
		CanaryTokens: CanaryTokens{
			Enabled: false,
		},
		MCPInputScanning: MCPInputScanning{
			Enabled:      false,
			OnParseError: ActionBlock,
		},
		MCPToolScanning: MCPToolScanning{
			Enabled: false,
		},
		MCPToolPolicy: MCPToolPolicy{
			Enabled:       false,
			QuarantineDir: filepath.Join(os.TempDir(), "pipelock-quarantine"),
		},
		Defer: DeferConfig{
			Enabled:              true,
			TimeoutSeconds:       2,
			MaxPending:           64,
			MaxPendingPerSession: 8,
			MaxPendingBytes:      1024 * 1024,
			MaxCascadeDepth:      8,
		},
		GitProtection: GitProtection{
			Enabled:         false,
			AllowedBranches: []string{"feature/*", "fix/*", "main", "master"},
			PrePushScan:     true,
		},
		ResponseScanning: ResponseScanning{
			Enabled:                        true,
			Action:                         "warn",
			SizeExemptScanMaxBytes:         DefaultSizeExemptScanMaxBytes,
			SizeExemptScanMaxInflightBytes: DefaultSizeExemptScanMaxInflightBytes,
			SSEStreaming: GenericSSEScanning{
				Enabled:       true,
				Action:        ActionBlock,
				MaxEventBytes: 64 * 1024,
			},
			Patterns: []ResponseScanPattern{
				{Name: "Prompt Injection", Regex: `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`},
				{Name: "System Override", Regex: `(?im)^\s*system\s*:`},
				{Name: "Role Override", Regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`},
				{Name: "New Instructions", Regex: `(?i)(new|updated|revised)\s+(instructions|directives|rules|prompt)`},
				{Name: "Jailbreak Attempt", Regex: `(?i)((?-i:\bDAN\b)|developer\s+mode|sudo\s+mode|unrestricted\s+mode)`},
				{Name: "Hidden Instruction", Regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instructions?\s*[:=]|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`},
				{Name: "Behavior Override", Regex: `(?i)from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+`},
				{Name: "Encoded Payload", Regex: `(?i)(decode\s+(this|the\s+following)\s+(from\s+)?base64\s+and\s+(execute|run|follow)|eval\s*\(\s*atob\s*\()`},
				{Name: "Tool Invocation", Regex: `(?i)you\s+must\s+(\w+\s+)?(call|execute|run|invoke)\s+(the|this|a)\s+(\w+\s+)?(function|tool|command|api|endpoint)`},
				{Name: "Authority Escalation", Regex: `(?i)you\s+(now\s+)?have\s+(full\s+)?(admin|root|system|superuser|elevated)\s+(access|privileges|permissions|rights)`},
				{Name: "Instruction Downgrade", Regex: `(?i)(treat|consider|regard|reinterpret|downgrade)\s+((?:the|all)\s+)?(previous|prior|above|earlier|system|policy|original|existing)\s+(\w+\s+)?(text|instructions?|rules|directives|guidelines|safeguards|constraints|controls|checks|context|prompt|policies|guardrails|parameters)\s+((as|to)\s+)?(historical|outdated|deprecated|optional|background|secondary|non-binding|non-authoritative|informational|advisory)`},
				{Name: "Instruction Dismissal", Regex: `(?i)(set|put)\s+(the\s+)?(previous|prior|above|earlier|system|original)\s+(\w+\s+)?(instructions?|directives|rules|constraints|context|prompt|safeguards|guidelines|policies|guardrails)\s+(aside|away|to\s+(one|the)\s+side)`},
				{Name: "Priority Override", Regex: `(?i)\bprioritize\s+(the\s+)?(task|user|current|new|latest)\s+(request|message|input|instructions?|prompt)`},
				// State/control poisoning - detect credential solicitation,
				// memory persistence, and preference manipulation in tool results.
				// Credential Solicitation is direction-anchored (verb + credential
				// noun + an explicit "send it back to the requester" cue in the same
				// local solicitation clause). Bare setup docs like "provide your API
				// key in config" and defensive docs like "never send your API key to
				// us" are ordinary documentation, not attacks. Mirrors the immutable
				// core floor in internal/scanner/core.go.
				{Name: "Credential Solicitation", Regex: CredentialSolicitationRegex},
				{Name: "Markdown Link Credential Exfiltration", Regex: MarkdownLinkCredentialExfilRegex},
				{Name: "Markdown Link Credential Value Exfiltration", Regex: MarkdownLinkCredentialValueExfilRegex},
				{Name: "Markdown Link Credential Follow Exfiltration", Regex: MarkdownLinkCredentialFollowExfilRegex},
				{Name: "Credential Path Directive", Regex: CredentialPathDirectiveRegex},
				{Name: "Auth Material Requirement", Regex: AuthMaterialRequirementRegex},
				{Name: "Memory Persistence Directive", Regex: `(?is)\b(save|store|remember|retain|persist|record|cache)\b.{0,40}\b(this|these|that|it|the)\b.{0,60}\b(for future|for later|across sessions?|next session|next time|future tasks?|future sessions?|for all future|subsequent|permanently|from now on|going forward|in all future)\b`},
				{Name: "Preference Poisoning", Regex: `(?is)\b(from now on|always|going forward|in future)\b.{0,80}\b(prefer|prioritize|trust|choose|use|default to)\b.{0,60}\b(this tool|that tool|my tool|the external|the remote)\b`},
				{Name: "Silent Credential Handling", Regex: `(?is)\b(do not|don'?t|never)\s+(mention|display|show|tell|reveal|log|report)\b.{0,100}\b(password|token|secret|credential|private[_ -]?key|api[_ -]?key)\b`},
				// Covert action directives - instructions to perform actions
				// secretly, silently, or without the user's knowledge.
				{Name: "Covert Action Directive", Regex: `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post|exfiltrat\w*|leak|stream|transmit|relay|forward|smuggle)\b`},
				// Model-specific instruction boundary tokens - ChatML, Llama, Mistral.
				// Presence in tool output is a strong injection signal.
				{Name: "Instruction Boundary", Regex: `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`},
				{Name: "Spanish Instruction Override", Regex: `(?i)\b(ignora|omite|olvida|desobedece|descarta)\b.{0,30}\b(las\s+)?(instrucciones|indicaciones|directivas|reglas)\b.{0,30}\b(anteriores|previas|precedentes|de\s+arriba)\b`},
				{Name: "Spanish System Prompt Disclosure", Regex: `(?i)\b(muestra|revela|imprime|expone|dime)\b.{0,40}\b(prompt|mensaje)\s+(del\s+)?sistema\b`},
				{Name: "Cross-Lingual Instruction Override", Regex: `(?i)\b(ignore|disregard|forget|abandon|ignora|omite|olvida|desobedece|descarta)\b.{0,40}\b(previous|prior|above|earlier|anteriores|previas|precedentes|de\s+arriba)\b.{0,40}\b(instructions?|instrucciones|indicaciones|directivas|reglas|prompts?|context|constraints?|policies|guardrails)\b`},
				{Name: "Cross-Lingual System Prompt Disclosure", Regex: `(?i)\b(show|reveal|print|display|dump|muestra|revela|imprime|expone|dime)\b.{0,40}\b(system\s+prompt|prompt\s+(del\s+)?sistema|mensaje\s+(del\s+)?sistema)\b`},
				// CJK injection patterns - Chinese, Japanese, Korean prompt
				// injection phrases sourced from published attack research,
				// jailbreak datasets, and security disclosures. Patterns use
				// .{0,N} ranges instead of \b because CJK has no word boundaries.
				{Name: "CJK Instruction Override ZH", Regex: `(忽略|无视|忽视|不理|不要遵[循守]|放弃|跳过).{0,10}(之前|以上|上述|以前|上面|先前|前面).{0,8}(所有|全部|一切)?.{0,6}(指令|指示|说明|规则|命令|提示|约束|限制)`},
				{Name: "CJK Instruction Override JP", Regex: `(以前|前|上記|これまで|今まで).{0,6}(指示|命令|ルール|規則|指令).{0,6}(すべて|全て|全部)?.{0,4}(無視|忘れ|従わな|捨て)`},
				{Name: "CJK Instruction Override KR", Regex: `(이전|위|앞|기존).{0,6}(모든\s*)?(지시|지침|명령|규칙|지령).{0,6}(무시|잊어|따르지|어기|무효)`},
				{Name: "CJK Jailbreak Mode", Regex: `(开发者模式|无限制模式|開発者モード|制限なしモード|개발자\s*모드|제한\s*없는\s*모드|没有任何?限制|制限.{0,4}(解除|無視)|제한.{0,4}(해제|무시))`},
			},
		},
		Logging: LoggingConfig{
			Format:         DefaultLogFormat,
			Output:         DefaultLogOutput,
			IncludeAllowed: true,
			IncludeBlocked: true,
		},
		MCPWSListener: MCPWSListener{
			MaxConnections: 100,
		},
		SessionProfiling: SessionProfiling{
			AnomalyAction:          ActionWarn,
			DomainBurst:            5,
			WindowMinutes:          5,
			VolumeSpikeRatio:       3.0,
			MaxSessions:            1000,
			SessionTTLMinutes:      30,
			CleanupIntervalSeconds: 60,
		},
		AdaptiveEnforcement: AdaptiveEnforcement{
			LevelDurationSeconds:      300,
			DeescalationCheckSeconds:  30,
			CooperativeToolDownweight: true,
		},
		TLSInterception: TLSInterception{
			Enabled: false,
			PassthroughDomains: []string{
				"*.googlevideo.com",
			},
			CertTTL:          DefaultCertTTL,
			CertCacheSize:    10000,
			MaxResponseBytes: 5 * 1024 * 1024, // 5MB
		},
		RequestBodyScanning: RequestBodyScanning{
			Enabled:      true,
			Action:       ActionWarn,
			MaxBodyBytes: 5 * 1024 * 1024, // 5MB
			ScanHeaders:  true,
			HeaderMode:   HeaderModeSensitive,
			SensitiveHeaders: []string{
				"Authorization",
				"Cookie",
				"X-Api-Key",
				"X-Token",
				"Proxy-Authorization",
				"X-Goog-Api-Key",
			},
		},
		SeedPhraseDetection: SeedPhraseDetection{
			Enabled:        ptrBool(true),
			MinWords:       12,
			VerifyChecksum: ptrBool(true),
		},
		Internal: []string{
			"0.0.0.0/8",
			"127.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
			"100.64.0.0/10",
			"224.0.0.0/4", // IPv4 multicast
			"::1/128",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8", // IPv6 multicast
		},
		ScanAPI: ScanAPI{
			Listen: "", // disabled by default
			RateLimit: ScanAPIRateLimit{
				RequestsPerMinute: 600,
				Burst:             50,
			},
			MaxBodyBytes: 1 << 20, // 1MB
			FieldLimits: ScanAPIFieldLimits{
				URL:       8192,
				Text:      512 * 1024, // 512KB
				Content:   512 * 1024, // 512KB
				Arguments: 512 * 1024, // 512KB
			},
			Timeouts: ScanAPITimeouts{
				Read:  "2s",
				Write: "2s",
				Scan:  "5s",
			},
			ConnectionLimit: 100,
			Kinds: ScanAPIKinds{
				URL:             true,
				DLP:             true,
				PromptInjection: true,
				ToolCall:        true,
			},
		},
		Rules: Rules{
			MinConfidence: ConfidenceMedium,
		},
		A2AScanning: A2AScanning{
			Enabled:                   false,
			Action:                    ActionWarn,
			ScanAgentCards:            true,
			DetectCardDrift:           true,
			SessionSmugglingDetection: true,
			MaxContextMessages:        100,
			MaxContexts:               1000,
			ScanRawParts:              true,
			MaxRawSize:                1 << 20, // 1MB encoded
		},
		MCPBinaryIntegrity: MCPBinaryIntegrity{
			Action: ActionBlock, // default action when hash verification fails
		},
		FlightRecorder: FlightRecorder{
			// Enabled by default so receipts ("verify the boundary") are on out
			// of the box. Emission still requires Dir != "" AND a signing key
			// (see server.go), so the default flip alone records nothing: a bare
			// Defaults() with no dir/key is inert. `pipelock init` generates both
			// and writes them into the config, which is what makes receipts live.
			// Footguns handled here: Redact stays on (receipts carry targets, so
			// without scrubbing they would persist secrets in the clear) and
			// MaxEntriesPerFile caps file growth (rotation), so default-on cannot
			// silently fill the disk or leak. Evidence, not enforcement by default:
			// a recorder failure never blocks traffic unless RequireReceipts is
			// explicitly enabled by the operator.
			Enabled:            true,
			RequireReceipts:    false,
			CheckpointInterval: 1000,  // entries between signed checkpoints
			Redact:             true,  // DLP-scrub evidence before commit
			SignCheckpoints:    true,  // Ed25519 sign checkpoints
			MaxEntriesPerFile:  10000, // rotate files at this count
			Completeness: FlightRecorderCompleteness{
				HeartbeatInterval: "60s",
			},
			EvidenceHealth: FlightRecorderEvidenceHealth{
				Enabled:           ptrBool(true),
				SelfAuditInterval: "30s",
				MaxAnchorLag:      "24h",
			},
		},
		DashboardSnapshot: DashboardSnapshot{
			Interval: "10s",
		},
		MCPToolProvenance: MCPToolProvenance{
			Action:      ActionWarn,
			Mode:        ProvenanceModePipelock,
			OfflineOnly: true, // no network calls for verification
		},
		BehavioralBaseline: BehavioralBaseline{
			LearningWindow:   10,
			DeviationAction:  ActionWarn,
			SensitivitySigma: 2.0,
			PoisonResistance: true, // trimmed-mean scoring resists adversarial training data
			SeasonalityMode:  SeasonalityModeNone,
		},
		Airlock: Airlock{
			Triggers: AirlockTriggers{
				OnElevated:           AirlockTierNone,
				OnHigh:               AirlockTierSoft,
				OnCritical:           AirlockTierHard,
				AnomalyWindowMinutes: 5,
			},
			Timers: AirlockTimers{
				SoftMinutes:         10,
				HardMinutes:         5,
				DrainMinutes:        2,
				DrainTimeoutSeconds: 30,
			},
			ToolFreeze: AirlockToolFreeze{
				SnapshotOnEntry:  true,
				AllowCachedTools: true,
			},
		},
		BrowserShield: BrowserShield{
			Strictness:            ShieldStrictnessStandard,
			MaxShieldBytes:        5 * 1024 * 1024, // 5MB
			OversizeAction:        ShieldOversizeScanHead,
			StripExtensionProbing: true,
			StripHiddenTraps:      true,
			StripTrackingPixels:   true,
			ExemptDomains: []string{
				"challenges.cloudflare.com",
				"developer.mozilla.org",
				"docs.github.com",
				"github.dev",
				"go.dev",
				"hcaptcha.com",
				"pkg.go.dev",
				"vscode.dev",
				"www.recaptcha.net",
			},
		},
		Taint: TaintConfig{
			Enabled: true,
			AllowlistedDomains: []string{
				"docs.anthropic.com",
				"docs.github.com",
				"developer.mozilla.org",
			},
			ProtectedPaths: []string{
				"*/auth/*",
				"*/security/*",
				"*/.github/workflows/*",
				"*/.env*",
				"*/secrets*",
				"*/policy*",
				"*/sandbox*",
			},
			ElevatedPaths: []string{
				"*/config/*",
				"*/middleware*",
			},
			Policy:        ModeBalanced,
			RecentSources: 10,
		},
		MediationEnvelope: MediationEnvelope{},
		Learn: Learn{
			Enabled:    false,
			CaptureDir: "",
			Privacy: LearnPrivacy{
				SaltSource:             "",
				PublicAllowlistDefault: true, // reserved wire-shape default
			},
		},
		MediaPolicy: MediaPolicy{
			// Boolean fields left nil intentionally: all getters return the
			// security-preserving default when unset. Explicit YAML values
			// override, omission hits the default (enabled, strip audio+video,
			// strip metadata, log exposure). AllowedImageTypes and
			// MaxImageBytes also fall through to defaults via their getters.
		},
		HealthWatchdog: HealthWatchdog{
			Enabled:         true,
			IntervalSeconds: 2,
		},
		LearnLock: LearnLock{
			// Default off. The lock runtime is opt-in; if Enabled is
			// flipped on without the rest of the fields the validator
			// rejects the config at startup so a half-wired lock can
			// never silently downgrade to scanner-only.
			Enabled:           false,
			Mode:              LockModeShadow, // safe-by-default; live requires explicit opt-in
			MinimumSignatures: 1,
		},
		Conductor: Conductor{
			HonorRemoteKillSwitch: true,
			EmergencyStream:       ptrBool(true),
		},
	}
	// Mark all compiled defaults with provenance so the standard tier source
	// selector can distinguish them from user-supplied patterns. Set at
	// creation time (not during merge) so provenance survives any code path
	// that copies or reconstructs patterns.
	for i := range cfg.DLP.Patterns {
		cfg.DLP.Patterns[i].Compiled = true
	}
	for i := range cfg.ResponseScanning.Patterns {
		cfg.ResponseScanning.Patterns[i].Compiled = true
	}
	// Redaction defaults to disabled. Operators opt in via YAML; see the
	// redact package for the full schema.
	cfg.Redaction = redact.DefaultConfig()
	return cfg
}
