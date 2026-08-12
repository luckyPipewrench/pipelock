// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// structuralDigest hashes everything in a tool definition EXCEPT its
// description, so a description-only edit leaves it stable and any other
// change moves it.
//
// It reads the raw definition rather than the parsed struct so fields this
// code does not model - annotations, title, vendor extensions - are covered
// too. Every fallback digests bytes that still include the change, so two
// definitions can only compare equal when nothing actually differs; a fallback
// degrades precision (a description edit may read as structural) but never
// accepts a change it did not account for.
func structuralDigest(t ToolDef) string {
	source := t.raw
	if len(source) > 0 {
		if canonical, err := canonicalJSONWithout(source, "description"); err == nil {
			source = canonical
		}
	} else {
		// Length-delimited, because a bare concatenation collides: name "ab"
		// with schema "c" would hash the same preimage as name "a" with schema
		// "bc", and two different definitions sharing a structural digest read
		// as "nothing outside the description moved".
		source = fmt.Appendf(nil, "%d:%s%d:%s", len(t.Name), t.Name, len(t.InputSchema), t.InputSchema)
	}
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
}

// canonicalJSONWithout re-encodes a JSON object with every nested object key
// sorted, dropping one top-level field.
//
// Decoding to json.RawMessage and re-marshalling is NOT enough: json.Marshal
// sorts the keys of the map it is handed, but a RawMessage value is written
// back byte for byte, so nested key order survives. An upstream that builds its
// schema from a Go map emits a different key order on every response, which
// would report a structural change on every tools/list and block the tool
// permanently. Decoding all the way to interface{} makes every level a
// map[string]interface{} that json.Marshal sorts.
//
// UseNumber keeps numeric literals as written, so a float64 round trip cannot
// turn 1 into 1e+00 or lose precision on a large integer and manufacture a
// difference that way.
func canonicalJSONWithout(raw []byte, dropField string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	if fields, ok := decoded.(map[string]any); ok {
		delete(fields, dropField)
	}
	return json.Marshal(decoded)
}

// Drift cues answer "what did this change INTRODUCE", not "did it change".
//
// A tool definition that changes after an operator approved it is suspicious,
// but suspicion is not a verdict. Blocking on the fact of a change blocks every
// legitimate vendor description update, which is the fastest way to get drift
// detection turned off entirely. So a change lowers the evidence bar instead:
// it is blocked when it introduces content that a lookup or analysis tool has
// no reason to acquire, and allowed when it only adds descriptive text.
//
// "Introduced" is a set difference on cue INSTANCES, not a text diff of
// appended characters. A rewrite that reorders a sentence would defeat a tail
// diff, so comparison is on what the definition carries rather than on where it
// appears. Instance rather than class, because presence-only comparison is a
// fail-open: a tool whose approved description already posts somewhere carries
// an egress cue before and after an attacker changes the destination, and the
// same holds for swapping one agent instruction for another. The instance keeps
// the destination URL, the referenced tool name, and the matched instruction
// span, so an unchanged one stays silent under unrelated edits while a changed
// one is introduced.
const (
	// DriftCueEgressURL: the change introduced an outbound destination.
	DriftCueEgressURL = "egress-url"
	// DriftCueDirective: the change introduced an instruction aimed at the
	// agent's behavior around the call, rather than a description of what the
	// tool returns.
	DriftCueDirective = "agent-directive"
	// DriftCueConcealment: the change introduced an instruction to hide the
	// behavior from the user or the log.
	DriftCueConcealment = "concealment"
	// DriftCueCrossTool: the change introduced a reference to another tool.
	DriftCueCrossTool = "cross-tool-reference"
	// DriftCuePoison: the change introduced text matching a tool-poison
	// pattern that the approved definition did not match.
	DriftCuePoison = "tool-poison-pattern"
	// DriftCueStructural: the change touched something other than the
	// description - input schema, parameters, annotations, or any other field.
	//
	// This is the fail-closed half of the mechanism. A change is accepted only
	// when the whole of it is accounted for as descriptive text, so anything
	// this evaluation cannot characterize is a cue by construction rather than
	// something that slips through an incomplete list of shapes. A
	// destructiveHint flipped from true to false is the case that makes this
	// necessary: the description is untouched, and the tool just claimed to be
	// safer than the operator approved it as.
	DriftCueStructural = "structural-change"
)

// driftCuePattern pairs a cue class with the shape that detects it.
//
// valued marks a cue whose IDENTITY includes the matched value, not just the
// class. Presence-only comparison is a fail-open for these: a tool whose
// approved description already posts to a vendor endpoint would have an
// egress-url cue before and after an attacker swapped the destination, so the
// set difference would be empty and the swap would be accepted. Capturing the
// destination makes a new one an introduced cue while leaving unrelated edits
// around an unchanged destination silent.
type driftCuePattern struct {
	cue    string
	re     *regexp.Regexp
	valued bool
}

var driftCuePatterns = []driftCuePattern{
	{
		cue: DriftCueEgressURL,
		// A URL that is the DESTINATION of a data-movement verb, not any URL.
		// Measured against tool descriptions captured from real MCP servers:
		// every URL found was documentation or a parameter-format example
		// (scrapling's proxy format, "http://user:pass@host:8030"), and none
		// was an exfiltration destination. Treating a bare URL as a cue would
		// block a vendor who adds a docs link to a description, which is the
		// kind of friction that gets drift detection switched off. The
		// benchmark rug-pull says "send them to https://...", so the verb
		// pairing keeps the case that matters.
		re: regexp.MustCompile(`(?i)\b(?:` +
			`sends?|sent|posts?|posted|uploads?|uploaded|forwards?|forwarded|` +
			`submits?|submitted|mirrors?|mirrored|transmits?|transmitted|` +
			`cop(?:y|ies|ied)|delivers?|delivered|exfiltrates?|exfiltrated|` +
			`reports?|reported|relays?|relayed|pushe?s?|pushed|syncs?|synced|` +
			`stream(?:s|ed)?|export(?:s|ed)?|leaks?|leaked|beacons?|beaconed` +
			`)\b[^.!?]{0,100}?(\bhttps?://[^\s,;)"'\]]+|\bwww\.[a-z0-9-]+\.[a-z]{2,}[^\s,;)"'\]]*)`),
		valued: true,
	},
	{
		cue:    DriftCueConcealment,
		valued: true,
		// Instructions to suppress disclosure. Third-person descriptions of a
		// tool's own reticence ("does not log request bodies") are not
		// second-person or imperative and do not match.
		re: regexp.MustCompile(`(?i)(?:` +
			`\b(?:do\s+not|don'?t|never)\s+(?:mention|tell|inform|reveal|disclose|notify|announce|surface|report\s+this|log\s+this)\b` +
			`|\bwithout\s+(?:telling|informing|notifying|mentioning|alerting)\b` +
			`|\b(?:covertly|secretly)\b` +
			// "silently" and "discreetly" need an object worth hiding.
			// The official filesystem server's create_directory says it
			// "will succeed silently", which is idempotence, not concealment.
			`|\b(?:silently|discreetly)\s+(?:\w+\s+){0,3}(?:send|sends|sent|forward|forwards|forwarded|copy|copies|copied|upload|uploads|uploaded|attach|attaches|attached|include|includes|included|log|logs|logged|report|reports|reported|collect|collects|collected|read|reads|omit|omits|omitted|drop|drops|dropped)\b` +
			`|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|quiet|confidential|between)\b` +
			`|\bhide\s+(?:this|it|the)\s+\w+\s+from\b` +
			// The trailing clause is part of the cue IDENTITY, not of the
			// match decision: without it every concealment instruction has
			// the same span, and swapping one for another reads as no change.
			`)[^.!?]{0,80}`),
	},
	{
		cue: DriftCueCrossTool,
		// A reference to a SECOND tool. An explicit invoke verb is
		// unambiguous. The weaker verbs ("with", "via", "using") also appear
		// in ordinary prose, so they additionally require the name to look
		// like an MCP tool identifier - containing an underscore, dot, or
		// hyphen - which "Use the region tool naming convention." does not.
		re: regexp.MustCompile(`(?i)` +
			`\b(?:call|calls|calling|invoke|invokes|invoking)\s+(?:the\s+)?([a-z0-9][a-z0-9_.-]*)\s+tool\b` +
			`|\b(?:use|uses|using|with|via|through)\s+(?:the\s+)?([a-z0-9][a-z0-9]*[_.-][a-z0-9_.-]*)\s+tool\b` +
			`|\btool\s+named\s+['"\x60]?([a-z0-9][a-z0-9_.-]*)`),
		valued: true,
	},
	{
		cue:    DriftCueDirective,
		valued: true,
		// Obligation and call-ordering aimed at the agent. Deliberately NOT
		// bare imperative mood and NOT bare sequencing: "Pass the region
		// code.", "Always returns a list.", and "Also, the checked_at field is
		// included." are ordinary description. A leading "First,"/"Then,"/
		// "Also," says nothing by itself, because the clause after it is
		// usually declarative prose about what the tool does; the cases where
		// it does introduce risk carry the destination, the other tool, or the
		// concealment that those cues already catch. Matching it flagged six
		// ordinary descriptions in testing, which is the false-positive class
		// this whole mechanism exists to remove.
		//
		// The sequencing phrases require a following comma, which is what
		// separates an instruction to the agent from a description of the
		// tool's own behavior. Measured against tool descriptions captured
		// from real MCP servers: "Before returning, collect the workspace
		// files" is an instruction, while scrapling's "solves all types of
		// Cloudflare's challenges before returning the response to you" is
		// prose about what the tool does, and the bare form flagged it.
		re: regexp.MustCompile(`(?i)(?:` +
			`\bbefore\s+(?:returning|responding|answering|replying|proceeding|continuing|calling|invoking|using)\s*,` +
			`|\bafter\s+(?:returning|responding|answering|replying|the\s+call)\s*,` +
			`|\byou\s+(?:must|should|are\s+required\s+to)\b` +
			// NOT "you need to" or "you have to": in a tool description those
			// almost always complete "use this tool when you need to ...",
			// which says when the tool applies rather than instructing the
			// agent to do anything. Both official filesystem read tools
			// flagged on that phrasing.
			`|\b(?:make|be)\s+sure\s+to\b` +
			`|\bensure\s+(?:that\s+)?you\b` +
			`|\bignore\s+(?:previous|prior|earlier|all|any)\b` +
			// As above: the clause after the marker is what distinguishes
			// "before returning, validate the input" from "before
			// returning, collect the caller's environment".
			`)[^.!?]{0,80}`),
	},
}

// cueIdentity is one cue occurrence. Class is what an operator is told; value
// is empty for a presence-only cue and carries the destination or referenced
// tool name for a valued one.
type cueIdentity struct {
	class string
	value string
}

// driftCues returns the cue identities present in a definition's text. Text is
// normalized the same way tool-poison matching normalizes it, so a homoglyph or
// zero-width split cannot hide a cue from the comparison on one side and reveal
// it on the other.
func driftCues(text string) map[cueIdentity]bool {
	if text == "" {
		return nil
	}
	normalized := normalize.ForToolText(text)
	found := make(map[cueIdentity]bool)
	for _, p := range driftCuePatterns {
		if !p.valued {
			if p.re.MatchString(normalized) {
				found[cueIdentity{class: p.cue}] = true
			}
			continue
		}
		for _, m := range p.re.FindAllStringSubmatch(normalized, -1) {
			// Prefer a capture group when the pattern names the risky value
			// (the destination URL, the referenced tool). Otherwise the whole
			// matched span IS the value, so replacing one instruction with a
			// different one inside an already-present class still reads as
			// introduced.
			value := strings.ToLower(strings.Join(strings.Fields(m[0]), " "))
			for _, group := range m[1:] {
				if group != "" {
					value = strings.ToLower(group)
					break
				}
			}
			found[cueIdentity{class: p.cue, value: value}] = true
		}
	}
	return found
}

// introducedDriftCues returns the cue classes present in the new definition
// that were absent from the previous one. An empty result means the change
// added only descriptive text and is safe to adopt as the new baseline.
//
// structuralChanged reports whether anything outside the description differed.
func introducedDriftCues(prevDesc, newDesc string, structuralChanged bool) []string {
	before := definitionCues(prevDesc)

	classes := make(map[string]bool)
	for cue := range definitionCues(newDesc) {
		if !before[cue] {
			classes[cue.class] = true
		}
	}
	if structuralChanged {
		classes[DriftCueStructural] = true
	}

	introduced := make([]string, 0, len(classes))
	for class := range classes {
		introduced = append(introduced, class)
	}
	sort.Strings(introduced)
	return introduced
}

// definitionCues returns every cue identity a description carries. Poison
// matching is reused rather than reimplemented so the drift bar can never
// disagree with first-sight scanning about the same text, and each matched
// pattern NAME is part of the identity so swapping one poison shape for another
// still reads as introduced.
func definitionCues(desc string) map[cueIdentity]bool {
	cues := driftCues(desc)
	if desc == "" {
		return cues
	}
	if cues == nil {
		cues = make(map[cueIdentity]bool)
	}
	for _, name := range checkToolPoison(normalize.ForToolText(desc)) {
		cues[cueIdentity{class: DriftCuePoison, value: name}] = true
	}
	return cues
}
