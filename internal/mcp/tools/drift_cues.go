// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"

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
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(source, &fields); err == nil {
			delete(fields, "description")
			// json.Marshal sorts map keys, so this is canonical.
			if encoded, err := json.Marshal(fields); err == nil {
				source = encoded
			}
		}
	} else {
		source = append([]byte(t.Name), t.InputSchema...)
	}
	sum := sha256.Sum256(source)
	return hex.EncodeToString(sum[:])
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
// "Introduced" is a set difference on cue CLASSES, not a text diff of appended
// characters. A rewrite that reorders a sentence would defeat a tail diff, and
// a tool whose approved description already carried a URL would otherwise be
// blocked forever by its next benign edit. Comparing which classes are present
// before and after is stable under both.
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
type driftCuePattern struct {
	cue string
	re  *regexp.Regexp
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
			`)\b[^.!?]{0,100}?(?:\bhttps?://|\bwww\.[a-z0-9-]+\.[a-z]{2,})`),
	},
	{
		cue: DriftCueConcealment,
		// Instructions to suppress disclosure. Third-person descriptions of a
		// tool's own reticence ("does not log request bodies") are not
		// second-person or imperative and do not match.
		re: regexp.MustCompile(`(?i)` +
			`\b(?:do\s+not|don'?t|never)\s+(?:mention|tell|inform|reveal|disclose|notify|announce|surface|report\s+this|log\s+this)\b` +
			`|\bwithout\s+(?:telling|informing|notifying|mentioning|alerting)\b` +
			`|\b(?:silently|covertly|secretly|discreetly)\b` +
			`|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|quiet|confidential|between)\b` +
			`|\bhide\s+(?:this|it|the)\s+\w+\s+from\b`),
	},
	{
		cue: DriftCueCrossTool,
		// A reference to a SECOND tool. An explicit invoke verb is
		// unambiguous. The weaker verbs ("with", "via", "using") also appear
		// in ordinary prose, so they additionally require the name to look
		// like an MCP tool identifier - containing an underscore, dot, or
		// hyphen - which "Use the region tool naming convention." does not.
		re: regexp.MustCompile(`(?i)` +
			`\b(?:call|calls|calling|invoke|invokes|invoking)\s+(?:the\s+)?[a-z0-9][a-z0-9_.-]*\s+tool\b` +
			`|\b(?:use|uses|using|with|via|through)\s+(?:the\s+)?[a-z0-9][a-z0-9]*[_.-][a-z0-9_.-]*\s+tool\b` +
			`|\btool\s+named\s+['"\x60]?[a-z0-9][a-z0-9_.-]*`),
	},
	{
		cue: DriftCueDirective,
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
		re: regexp.MustCompile(`(?i)` +
			`\bbefore\s+(?:returning|responding|answering|replying|proceeding|continuing|calling|invoking|using)\s*,` +
			`|\bafter\s+(?:returning|responding|answering|replying|the\s+call)\s*,` +
			`|\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to)\b` +
			`|\b(?:make|be)\s+sure\s+to\b` +
			`|\bensure\s+(?:that\s+)?you\b` +
			`|\bignore\s+(?:previous|prior|earlier|all|any)\b`),
	},
}

// driftCues returns the cue classes present in a definition's text, sorted and
// deduplicated. Text is normalized the same way tool-poison matching normalizes
// it, so a homoglyph or zero-width split cannot hide a cue from the comparison
// on one side and reveal it on the other.
func driftCues(text string) []string {
	if text == "" {
		return nil
	}
	normalized := normalize.ForToolText(text)
	var cues []string
	for _, p := range driftCuePatterns {
		if p.re.MatchString(normalized) {
			cues = append(cues, p.cue)
		}
	}
	sort.Strings(cues)
	return cues
}

// introducedDriftCues returns the cue classes present in the new definition
// that were absent from the previous one. An empty result means the change
// added only descriptive text and is safe to adopt as the new baseline.
//
// structuralChanged reports whether anything outside the description differed.
func introducedDriftCues(prevDesc, newDesc string, structuralChanged bool) []string {
	before := make(map[string]bool, len(driftCuePatterns)+1)
	for _, cue := range definitionCues(prevDesc) {
		before[cue] = true
	}

	var introduced []string
	for _, cue := range definitionCues(newDesc) {
		if !before[cue] {
			introduced = append(introduced, cue)
		}
	}
	if structuralChanged {
		introduced = append(introduced, DriftCueStructural)
		sort.Strings(introduced)
	}
	return introduced
}

// definitionCues returns every cue class a description carries, including a
// single collapsed entry for any tool-poison pattern hit. Poison matching is
// reused rather than reimplemented so the drift bar can never disagree with
// first-sight scanning about the same text.
func definitionCues(desc string) []string {
	cues := driftCues(desc)
	if desc != "" && len(checkToolPoison(normalize.ForToolText(desc))) > 0 {
		cues = append(cues, DriftCuePoison)
		sort.Strings(cues)
	}
	return cues
}
