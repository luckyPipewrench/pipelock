// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/binary"
	"net/url"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const (
	dnsHeaderLen = 12
	// dnsMaxMessageLen is the RFC 1035 / RFC 8484 ceiling: the two-byte TCP
	// length prefix cannot describe a longer message. A longer body is not a
	// DNS message and keeps the checks for an opaque body.
	dnsMaxMessageLen = 65535
	dnsMaxNameLen    = 255
	dnsMaxLabelLen   = 63
	dnsMaxNameSteps  = 128
	dnsTypeOPT       = 41
	dnsTypeTXT       = 16
	dnsPointerMarker = 0xC0
	dnsLabelTypeMask = 0xC0

	// dnsQueryParam is the RFC 8484 GET parameter. The raw key must match
	// these bytes; a different spelling keeps the whole-value entropy check.
	dnsQueryParam = "dns"
)

// dnsName is one question or record name, with labels in wire order and
// without the root label.
type dnsName struct {
	labels []string
}

// dnsMessage is a DNS message that a strict parse consumed completely.
type dnsMessage struct {
	names []dnsName
	// blobs are record RDATA values and, for OPT records, each EDNS option
	// payload. Padding is included; it is ordinary RDATA.
	blobs [][]byte
	// fixed is every fixed-width field the parse consumed: the header, each
	// question's type and class, each record's type, class, TTL and length,
	// each EDNS option code and length, and every compression pointer. None of it is a name or a payload,
	// but a sender chooses those bytes, and a message of many empty records
	// would otherwise carry eight unscored bytes per record.
	fixed []byte
}

// DNSPayloadInspection is the DLP and entropy view of one DNS message.
// Parsed is false when payload is not a strict DNS message; callers then
// keep the checks they already apply to an opaque body. DLPTexts and
// EntropyTexts replace the opaque body in those checks; the caller runs them
// through its own pipeline, so suppressions, disabled patterns, exemptions
// and pattern actions apply to a DNS message exactly as to any other body.
type DNSPayloadInspection struct {
	Parsed       bool
	DLPTexts     []string
	EntropyTexts []string
}

// InspectDNSPayload parses payload as a DNS message and returns the pieces
// its DLP and entropy checks must see.
func (s *Scanner) InspectDNSPayload(payload []byte) DNSPayloadInspection {
	msg, ok := parseDNSMessage(payload)
	if !ok {
		return DNSPayloadInspection{}
	}
	return DNSPayloadInspection{
		Parsed:       true,
		DLPTexts:     msg.dlpTexts(),
		EntropyTexts: msg.entropyTexts(),
	}
}

// parseDNSQuery reports the DNS message carried by an RFC 8484 GET query.
// The raw query must contain no ';', exactly one raw key spelled dns, and a
// value that is canonical unpadded base64url. Anything else is not this
// message, and the caller keeps the whole-value check.
func parseDNSQuery(rawQuery string) (dnsMessage, bool) {
	if rawQuery == "" || strings.Contains(rawQuery, ";") {
		return dnsMessage{}, false
	}
	var rawValue string
	found := 0
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			return dnsMessage{}, false
		}
		rawKey, value, ok := strings.Cut(part, "=")
		if !ok || rawKey != dnsQueryParam {
			return dnsMessage{}, false
		}
		found++
		rawValue = value
	}
	if found != 1 {
		return dnsMessage{}, false
	}
	return parseDNSQueryValue(rawValue)
}

// parseDNSQueryValue decodes one raw dns query value: canonical unpadded
// base64url of a message the strict parser accepts.
func parseDNSQueryValue(rawValue string) (dnsMessage, bool) {
	decoded, err := url.QueryUnescape(rawValue)
	if err != nil || decoded == "" || strings.ContainsRune(decoded, '=') {
		return dnsMessage{}, false
	}
	wire, err := base64.RawURLEncoding.DecodeString(decoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(wire) != decoded {
		return dnsMessage{}, false
	}
	return parseDNSMessage(wire)
}

// dnsQueryDLPTexts returns the DLP views of every DNS message a query may
// carry, for DLP only. Unlike parseDNSQuery it does not require the query to
// be a pure RFC 8484 request: any parameter whose key decodes to dns, in any
// spelling, beside any other parameters, is tried. These views only add
// targets, so reading more than the strict form cannot relax a verdict; the
// entropy relief stays on parseDNSQuery's strict form.
func dnsQueryDLPTexts(rawQuery string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(rawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		rawKey, rawValue, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if key, err := url.QueryUnescape(rawKey); err != nil || key != dnsQueryParam {
			continue
		}
		if msg, ok := parseDNSQueryValue(rawValue); ok {
			out = append(out, msg.dlpTexts()...)
		}
	}
	return out
}

func parseDNSMessage(msg []byte) (dnsMessage, bool) {
	if len(msg) < dnsHeaderLen || len(msg) > dnsMaxMessageLen {
		return dnsMessage{}, false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	if qd > len(msg) || an > len(msg) || ns > len(msg) || ar > len(msg) {
		return dnsMessage{}, false
	}
	var out dnsMessage
	out.fixed = append(out.fixed, msg[:dnsHeaderLen]...)
	off := dnsHeaderLen
	var ok bool
	for range qd {
		off, ok = consumeDNSQuestion(msg, off, &out)
		if !ok {
			return dnsMessage{}, false
		}
	}
	for range an + ns + ar {
		off, ok = consumeDNSRR(msg, off, &out)
		if !ok {
			return dnsMessage{}, false
		}
	}
	if off != len(msg) {
		return dnsMessage{}, false
	}
	return out, true
}

func consumeDNSQuestion(msg []byte, off int, out *dnsMessage) (int, bool) {
	labels, pointers, next, ok := readDNSName(msg, off)
	if !ok || next+4 > len(msg) {
		return 0, false
	}
	out.names = append(out.names, dnsName{labels: labels})
	out.fixed = append(out.fixed, pointers...)
	out.fixed = append(out.fixed, msg[next:next+4]...)
	return next + 4, true
}

func consumeDNSRR(msg []byte, off int, out *dnsMessage) (int, bool) {
	labels, pointers, next, ok := readDNSName(msg, off)
	if !ok || next+10 > len(msg) {
		return 0, false
	}
	out.names = append(out.names, dnsName{labels: labels})
	out.fixed = append(out.fixed, pointers...)
	out.fixed = append(out.fixed, msg[next:next+10]...)
	typ := binary.BigEndian.Uint16(msg[next:])
	rdlen := int(binary.BigEndian.Uint16(msg[next+8:]))
	rdataAt := next + 10
	if rdataAt+rdlen > len(msg) {
		return 0, false
	}
	rdata := append([]byte(nil), msg[rdataAt:rdataAt+rdlen]...)
	out.blobs = append(out.blobs, rdata)
	if typ == dnsTypeTXT {
		// A TXT record is one or more length-prefixed character-strings. The
		// raw RDATA keeps each length octet between them, which can break a
		// value split across strings, so the joined text is a view too.
		if joined, ok := joinTXTStrings(rdata); ok {
			out.blobs = append(out.blobs, joined)
		}
	}
	if typ == dnsTypeOPT && !appendEDNSOptionPayloads(rdata, out) {
		return 0, false
	}
	return rdataAt + rdlen, true
}

// joinTXTStrings concatenates the character-strings of TXT RDATA. It reports
// false when the RDATA is not a whole sequence of character-strings.
func joinTXTStrings(rdata []byte) ([]byte, bool) {
	var joined []byte
	for off := 0; off < len(rdata); {
		n := int(rdata[off])
		if off+1+n > len(rdata) {
			return nil, false
		}
		joined = append(joined, rdata[off+1:off+1+n]...)
		off += 1 + n
	}
	return joined, len(joined) > 0
}

func appendEDNSOptionPayloads(rdata []byte, out *dnsMessage) bool {
	off := 0
	for off < len(rdata) {
		if off+4 > len(rdata) {
			return false
		}
		length := int(binary.BigEndian.Uint16(rdata[off+2:]))
		out.fixed = append(out.fixed, rdata[off:off+4]...)
		off += 4
		if length < 0 || off+length > len(rdata) {
			return false
		}
		out.blobs = append(out.blobs, append([]byte(nil), rdata[off:off+length]...))
		off += length
	}
	return true
}

// readDNSName reads one domain name. Compression pointers must land inside
// the message. A pointer loop never reaches a root label, so the
// dnsMaxNameSteps bound rejects it; no separate visited set is needed, and
// one could not change a verdict. Label types 0x40 and 0x80 are rejected.
// next is the first byte after this name on the wire at the caller's offset.
func readDNSName(msg []byte, start int) (labels []string, pointers []byte, next int, ok bool) {
	offset := start
	jumped := false
	next = start
	uncompressed := 1
	for range dnsMaxNameSteps {
		if offset < 0 || offset >= len(msg) {
			return nil, nil, 0, false
		}
		marker := msg[offset]
		switch marker & dnsLabelTypeMask {
		case 0:
			length := int(marker)
			if length == 0 {
				if uncompressed > dnsMaxNameLen {
					return nil, nil, 0, false
				}
				if !jumped {
					next = offset + 1
				}
				return labels, pointers, next, true
			}
			if length > dnsMaxLabelLen || offset+1+length > len(msg) {
				return nil, nil, 0, false
			}
			labels = append(labels, string(msg[offset+1:offset+1+length]))
			uncompressed += 1 + length
			if uncompressed > dnsMaxNameLen {
				return nil, nil, 0, false
			}
			offset += 1 + length
			if !jumped {
				next = offset
			}
		case dnsPointerMarker:
			if offset+1 >= len(msg) {
				return nil, nil, 0, false
			}
			pointers = append(pointers, msg[offset], msg[offset+1])
			ptr := int(marker&0x3F)<<8 | int(msg[offset+1])
			if ptr >= len(msg) {
				return nil, nil, 0, false
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ptr
		default:
			return nil, nil, 0, false
		}
	}
	return nil, nil, 0, false
}

func (m dnsMessage) dlpTexts() []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(text string) {
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	for _, name := range m.names {
		for _, label := range name.labels {
			add(label)
		}
		if len(name.labels) == 0 {
			continue
		}
		add(strings.Join(name.labels, "."))
		add(strings.Join(name.labels, ""))
	}
	// One view of every label of every name joined without separators, so a
	// value split across two names is seen whole. The wire bytes between the
	// names can be printable (a type or class of '.' bytes), which is enough
	// to break the match in the message's own decoded view.
	if len(m.names) > 1 {
		var all []string
		for _, name := range m.names {
			all = append(all, name.labels...)
		}
		add(strings.Join(all, ""))
	}
	for _, blob := range m.blobs {
		add(string(blob))
	}
	add(string(m.fixed))
	return out
}

// dnsEntropyPart is one scored piece of a DNS message and the text the
// entropy gate measures for it.
type dnsEntropyPart struct {
	part string
	text string
}

// entropyParts returns every piece of the message in the form the entropy
// gate measures. Printable ASCII is measured as text, with labels folded to
// upper case so DNS 0x20 case randomization is not its own false positive.
// Anything else is measured as unpadded base64url, the alphabet the
// whole-message check scored before this parse existed: measured as a Go
// string, every byte above 0x7F would read as the same replacement rune and
// random binary would score as nearly uniform.
func (m dnsMessage) entropyParts() []dnsEntropyPart {
	var out []dnsEntropyPart
	for _, name := range m.names {
		for _, label := range name.labels {
			if label == "" {
				continue
			}
			out = append(out, dnsEntropyPart{"DNS label", dnsEntropySubject([]byte(label), true)})
		}
	}
	for _, blob := range m.blobs {
		if len(blob) == 0 {
			continue
		}
		out = append(out, dnsEntropyPart{"DNS rdata", dnsEntropySubject(blob, false)})
	}
	out = append(out, dnsEntropyPart{"DNS fixed fields", base64.RawURLEncoding.EncodeToString(m.fixed)})
	return out
}

func (m dnsMessage) entropyTexts() []string {
	parts := m.entropyParts()
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, p.text)
	}
	return out
}

func dnsEntropySubject(b []byte, foldCase bool) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return base64.RawURLEncoding.EncodeToString(b)
		}
	}
	if foldCase {
		return normalize.ASCIIUpper(string(b))
	}
	return string(b)
}

// dnsMessageEntropy scores every piece of the message with the URL entropy
// gate: labels, record payloads, EDNS option payloads and the fixed-width
// fields, each as returned by entropyParts.
func (s *Scanner) dnsMessageEntropy(msg dnsMessage) (entropyFinding, bool) {
	parts := msg.entropyParts()
	for _, p := range parts {
		if len(p.text) < s.entropyMinLen {
			continue
		}
		if entropy := payloadEntropy(p.text); entropy > s.entropyThreshold {
			return entropyFinding{part: p.part, entropy: entropy}, true
		}
	}
	// Data split across many short pieces, each under the length floor or
	// individually low, is measured once more as one stable, separator-free
	// view of every piece, the same shape the request-body scanner joins.
	// Sorting makes the view independent of piece order. Measured on an
	// ordinary query the view stays low: the benign RFC 8484 Bench pair
	// scores 3.73, under even the stricter 4.00 Bench threshold, while four
	// random 19-character labels score 4.56.
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		texts = append(texts, p.text)
	}
	sort.Strings(texts)
	joined := strings.Join(texts, "")
	if len(joined) >= s.entropyMinLen {
		if entropy := payloadEntropy(joined); entropy > s.entropyThreshold {
			return entropyFinding{part: "DNS message", entropy: entropy}, true
		}
	}
	return entropyFinding{}, false
}
