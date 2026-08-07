// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	maxEvidenceDoctorFindings = 40

	// maxEvidenceDoctorFiles bounds the doctor's own read. It is deliberately
	// larger than recorder.MaxEvidenceReadDirectoryEntries because the two caps
	// exist for different reasons: that ceiling guards the evidence READ paths
	// (query, verification, the dashboard), where a partial read would present
	// incomplete evidence as complete, so it must fail closed. The doctor only
	// reports, so a partial view is merely incomplete rather than dangerous -
	// and refusing to read an over-cap directory would blind the one tool an
	// operator has for diagnosing exactly that state. A truncated scan is
	// therefore reported, never treated as healthy, and never allowed to exit
	// zero.
	//
	// Recorder resume is not gated by that ceiling at all. It enumerates a
	// session's shards uncapped to find the newest one holding entries, which
	// may mean skipping several empty shards, and then reads only that tail
	// under the bounded per-file limits. This budget still needs to exceed the
	// ceiling so the doctor stays useful on the over-cap directories that
	// motivated it.
	maxEvidenceDoctorFiles = 16 * recorder.MaxEvidenceReadDirectoryEntries

	// maxDoctorRefsPerFinding bounds per-finding detail. A directory with
	// thousands of conflicts would otherwise emit megabytes of references and
	// bury the summary an operator actually needs.
	maxDoctorRefsPerFinding = 3
)

type evidenceDoctorReport struct {
	Dir           string
	FilesRead     int
	Findings      []evidenceDoctorFinding
	Truncated     bool
	ScanTruncated bool
	FilesSkipped  int
}

func (r evidenceDoctorReport) Damaged() bool {
	return len(r.Findings) > 0
}

// Conclusive reports whether the scan covered the whole directory. An
// inconclusive scan must never be presented as healthy: absence of findings
// over a partial view is not evidence of an intact chain.
func (r evidenceDoctorReport) Conclusive() bool {
	return !r.ScanTruncated
}

type evidenceDoctorFinding struct {
	Kind    string
	Message string
}

type doctorEntryRef struct {
	Session  string
	File     string
	Seq      uint64
	PrevHash string
	Hash     string
	RawRef   string
}

type doctorChainRef struct {
	Chain    string
	File     string
	Seq      uint64
	PrevHash string
	Hash     string
	Label    string
}

type evidenceDoctor struct {
	dir           string
	location      recorder.EvidenceLocation
	filesRead     int
	findings      []evidenceDoctorFinding
	truncated     bool
	scanTruncated bool
	filesSkipped  int
	sidecarFiles  map[string]struct{}
	recorderRefs  []doctorEntryRef
	receiptRefs   map[string][]doctorChainRef
	escrowRefs    map[string][]doctorEntryRef
}

func doctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor DIR",
		Short: "Detect structural damage in a flight-recorder evidence directory",
		Long: `Scan a flight-recorder evidence directory without modifying it.

The doctor reports duplicate sequence numbers, forked prev_hash values,
receipt-chain sequence collisions, raw-escrow sidecar collisions, chain gaps,
and missing genesis records. It exits nonzero when damage is found so operators
can use it in CI.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := runEvidenceDoctor(args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			printEvidenceDoctorReport(cmd, report)
			if report.Damaged() {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("evidence doctor found structural damage"))
			}
			if !report.Conclusive() {
				// Fail closed: a partial scan cannot certify an intact chain, so
				// a CI gate must not go green on it.
				return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("evidence doctor scan was incomplete; absence of damage not confirmed"))
			}
			return nil
		},
	}
	return cmd
}

func runEvidenceDoctor(dir string) (evidenceDoctorReport, error) {
	cleanDir := filepath.Clean(dir)
	info, err := os.Stat(cleanDir)
	if err != nil {
		return evidenceDoctorReport{}, fmt.Errorf("stat evidence directory: %w", err)
	}
	if !info.IsDir() {
		return evidenceDoctorReport{}, fmt.Errorf("%q is not a directory", dir)
	}

	locations, err := recorder.DiscoverEvidenceLocations(cleanDir)
	if err != nil {
		// Discovery failures are structural evidence findings, not command
		// configuration errors. Preserve the doctor's established fail-closed
		// report contract for an unreadable evidence root.
		return evidenceDoctorReport{
			Dir: cleanDir,
			Findings: []evidenceDoctorFinding{{
				Kind:    "directory_read_error",
				Message: "discover evidence locations: " + err.Error(),
			}},
		}, nil
	}
	if len(locations) == 0 {
		locations = []recorder.EvidenceLocation{{Root: cleanDir, Dir: cleanDir}}
	}
	report := evidenceDoctorReport{Dir: cleanDir}
	for _, location := range locations {
		d := &evidenceDoctor{
			dir:          location.Dir,
			location:     location,
			sidecarFiles: make(map[string]struct{}),
			receiptRefs:  make(map[string][]doctorChainRef),
			escrowRefs:   make(map[string][]doctorEntryRef),
		}
		d.scan()
		report.FilesRead += d.filesRead
		report.Findings = append(report.Findings, d.findings...)
		report.Truncated = report.Truncated || d.truncated
		report.ScanTruncated = report.ScanTruncated || d.scanTruncated
		report.FilesSkipped += d.filesSkipped
	}
	return report, nil
}

func (d *evidenceDoctor) scan() {
	dirEntries, skipped, err := readEvidenceDoctorDir(d.location)
	if err != nil {
		d.addFinding("directory_read_error", "read evidence directory: "+err.Error())
		return
	}
	if skipped > 0 {
		// Fail closed on coverage: the scan saw only part of the directory, so
		// a clean result below would be unearned. Record it as a finding so the
		// verdict cannot read healthy and the command cannot exit zero.
		d.scanTruncated = true
		d.filesSkipped = skipped
	}

	jsonlFiles := make([]string, 0)
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case isDoctorEvidenceJSONL(name):
			jsonlFiles = append(jsonlFiles, name)
		case isDoctorRawSidecar(name):
			d.sidecarFiles[name] = struct{}{}
		}
	}
	sort.Slice(jsonlFiles, func(i, j int) bool {
		aSession, aSeq, _ := parseDoctorEvidenceName(filepath.Base(jsonlFiles[i]), ".jsonl")
		bSession, bSeq, _ := parseDoctorEvidenceName(filepath.Base(jsonlFiles[j]), ".jsonl")
		if aSession != bSession {
			return aSession < bSession
		}
		return aSeq < bSeq
	})

	for _, path := range jsonlFiles {
		d.scanJSONL(path)
	}
	d.detectRecorderDamage()
	d.detectEscrowCollisions()
	d.detectReceiptDamage()
}

func readEvidenceDoctorDir(location recorder.EvidenceLocation) ([]os.DirEntry, int, error) {
	dirEntries, err := recorder.ReadEvidenceLocationEntries(location)
	if err != nil {
		return nil, 0, err
	}
	out := make([]os.DirEntry, 0)
	skipped := 0
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if isDoctorEvidenceJSONL(name) || isDoctorRawSidecar(name) {
			if len(out) >= maxEvidenceDoctorFiles {
				skipped++
				continue
			}
			out = append(out, de)
		}
	}
	return out, skipped, nil
}

func (d *evidenceDoctor) scanJSONL(name string) {
	data, err := recorder.ReadEvidenceLocationFileBounded(d.location, name, recorder.MaxEvidenceReadFileBytes)
	if err != nil {
		d.addFinding("file_read_error", fmt.Sprintf("%s: %v", name, err))
		return
	}
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(data))
	if err != nil {
		d.addFinding("malformed_jsonl", fmt.Sprintf("%s: %v", name, err))
		return
	}
	d.filesRead++
	if len(entries) == 0 {
		// A named evidence shard with no records is not normal steady state.
		// Report it rather than letting it contribute nothing: an emptied or
		// truncated shard produces no refs, so every downstream linkage check
		// would silently pass over it.
		d.addFinding("empty_evidence_file", fmt.Sprintf("%s: contains no entries", name))
		return
	}
	for _, entry := range entries {
		// Recompute rather than trust the stored hash. The doctor is what an
		// operator reaches for to tell fork damage apart from tampering, so it
		// cannot take an entry's own claim about its hash at face value: an
		// edited record whose hash field was left intact would otherwise be
		// reported healthy whenever no later record happens to reference it.
		computed := recorder.ComputeHash(entry)
		if computed != entry.Hash {
			d.addFinding("entry_hash_mismatch", fmt.Sprintf(
				"%s seq %d: stored hash %s does not match contents (computed %s)",
				name, entry.Sequence, shortDoctorHash(entry.Hash), shortDoctorHash(computed)))
		}
		ref := doctorEntryRef{
			Session: entry.SessionID,
			File:    name,
			Seq:     entry.Sequence,
			// Linkage is checked against the recomputed hash so a tampered
			// record cannot present a self-consistent chain.
			PrevHash: entry.PrevHash,
			Hash:     computed,
			RawRef:   entry.RawRef,
		}
		d.recorderRefs = append(d.recorderRefs, ref)
		if entry.RawRef != "" {
			d.escrowRefs[entry.RawRef] = append(d.escrowRefs[entry.RawRef], ref)
		}
		d.scanReceiptEntry(name, entry)
	}
}

func (d *evidenceDoctor) scanReceiptEntry(path string, entry recorder.Entry) {
	switch entry.Type {
	case "action_receipt":
		raw, ok := rawEntryDetail(entry)
		if !ok {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: action_receipt detail is not JSON", filepath.Base(path), entry.Sequence))
			return
		}
		r, err := receipt.Unmarshal(raw)
		if err != nil {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: decode action_receipt: %v", filepath.Base(path), entry.Sequence, err))
			return
		}
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: hash action_receipt: %v", filepath.Base(path), entry.Sequence, err))
			return
		}
		// Partition by session only, never by signer identity. A documented
		// signing-key rotation continues one writer chain, so keying on the
		// signer would split it and manufacture false missing-genesis and gap
		// findings in exactly the rotation case the docs say is supported. A
		// truncated signer hash is doubly unsuitable as a map key because
		// distinct keys can share a prefix. The signer stays an attribute on
		// the finding instead.
		chain := "v1 session=" + entry.SessionID
		d.receiptRefs[chain] = append(d.receiptRefs[chain], doctorChainRef{
			Chain:    chain,
			File:     filepath.Base(path),
			Seq:      r.ActionRecord.ChainSeq,
			PrevHash: r.ActionRecord.ChainPrevHash,
			Hash:     hash,
			Label:    "action_receipt signer=" + shortDoctorHash(r.SignerKey),
		})
	case "evidence_receipt":
		raw, ok := rawEntryDetail(entry)
		if !ok {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: evidence_receipt detail is not JSON", filepath.Base(path), entry.Sequence))
			return
		}
		var r contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: decode evidence_receipt: %v", filepath.Base(path), entry.Sequence, err))
			return
		}
		hash, err := contractreceipt.ReceiptHash(r)
		if err != nil {
			d.addFinding("malformed_receipt", fmt.Sprintf("%s seq %d: hash evidence_receipt: %v", filepath.Base(path), entry.Sequence, err))
			return
		}
		// SignerKeyID is an untrusted self-declared label, so it is not a safe
		// partition key either. Session only, signer as an attribute.
		chain := "v2 session=" + entry.SessionID
		d.receiptRefs[chain] = append(d.receiptRefs[chain], doctorChainRef{
			Chain:    chain,
			File:     filepath.Base(path),
			Seq:      r.ChainSeq,
			PrevHash: r.ChainPrevHash,
			Hash:     hash,
			Label:    string(r.PayloadKind) + " signer=" + r.Signature.SignerKeyID,
		})
	}
}

func rawEntryDetail(entry recorder.Entry) ([]byte, bool) {
	if len(entry.RawDetail) != 0 {
		return append([]byte(nil), entry.RawDetail...), true
	}
	switch detail := entry.Detail.(type) {
	case json.RawMessage:
		return append([]byte(nil), detail...), true
	default:
		data, err := json.Marshal(detail)
		if err != nil {
			return nil, false
		}
		return data, true
	}
}

func (d *evidenceDoctor) detectRecorderDamage() {
	bySessionSeq := make(map[string][]doctorEntryRef)
	bySession := make(map[string][]doctorChainRef)
	for _, ref := range d.recorderRefs {
		key := ref.Session + "\x00" + strconv.FormatUint(ref.Seq, 10)
		bySessionSeq[key] = append(bySessionSeq[key], ref)
		chain := "recorder session=" + ref.Session
		bySession[chain] = append(bySession[chain], doctorChainRef{
			Chain:    chain,
			File:     ref.File,
			Seq:      ref.Seq,
			PrevHash: ref.PrevHash,
			Hash:     ref.Hash,
			Label:    "recorder",
		})
	}
	for _, refs := range bySessionSeq {
		if len(refs) <= 1 {
			continue
		}
		session := refs[0].Session
		seq := refs[0].Seq
		d.addFinding("duplicate_recorder_seq", fmt.Sprintf(
			"session %q seq %d appears %d times: %s",
			session, seq, len(refs), formatEntryRefs(refs),
		))
		prevs := uniquePrevHashes(refs)
		if len(prevs) > 1 {
			d.addFinding("conflicting_recorder_prev_hash", fmt.Sprintf(
				"session %q seq %d has %d prev_hash values: %s",
				session, seq, len(prevs), formatEntryRefs(refs),
			))
		}
	}
	for chain, refs := range bySession {
		d.detectChainDamage(chain, refs, true)
	}
}

func (d *evidenceDoctor) detectEscrowCollisions() {
	for rawRef, refs := range d.escrowRefs {
		if len(refs) <= 1 {
			continue
		}
		d.addFinding("escrow_collision", fmt.Sprintf(
			"raw escrow sidecar %s is referenced by %d recorder entries: %s",
			rawRef, len(refs), formatEntryRefs(refs),
		))
	}
	bySeq := make(map[string][]doctorEntryRef)
	for _, ref := range d.recorderRefs {
		if _, ok := d.sidecarFiles[fmt.Sprintf("evidence-%s-%d.raw.enc", filepath.Base(ref.Session), ref.Seq)]; !ok {
			continue
		}
		key := ref.Session + "\x00" + strconv.FormatUint(ref.Seq, 10)
		bySeq[key] = append(bySeq[key], ref)
	}
	for _, refs := range bySeq {
		if len(refs) <= 1 {
			continue
		}
		d.addFinding("escrow_collision", fmt.Sprintf(
			"raw escrow sidecar evidence-%s-%d.raw.enc can hold only one payload but %d entries claim that session/seq: %s",
			filepath.Base(refs[0].Session), refs[0].Seq, len(refs), formatEntryRefs(refs),
		))
	}
}

func (d *evidenceDoctor) detectReceiptDamage() {
	for chain, refs := range d.receiptRefs {
		bySeq := make(map[uint64][]doctorChainRef)
		for _, ref := range refs {
			bySeq[ref.Seq] = append(bySeq[ref.Seq], ref)
		}
		for seq, dupes := range bySeq {
			if len(dupes) <= 1 {
				continue
			}
			d.addFinding("duplicate_receipt_chain_seq", fmt.Sprintf(
				"%s chain_seq %d appears %d times: %s",
				chain, seq, len(dupes), formatChainRefs(dupes),
			))
		}
		d.detectChainDamage(chain, refs, false)
	}
}

func (d *evidenceDoctor) detectChainDamage(chain string, refs []doctorChainRef, strictGenesis bool) {
	if len(refs) == 0 {
		return
	}
	bySeq := make(map[uint64][]doctorChainRef)
	seqs := make([]uint64, 0, len(refs))
	for _, ref := range refs {
		if _, ok := bySeq[ref.Seq]; !ok {
			seqs = append(seqs, ref.Seq)
		}
		bySeq[ref.Seq] = append(bySeq[ref.Seq], ref)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	genesisRefs := bySeq[0]
	if len(genesisRefs) == 0 {
		d.addFinding("missing_genesis", fmt.Sprintf("%s has no seq 0 genesis; first seq is %d", chain, seqs[0]))
	} else if !chainHasGenesis(genesisRefs, strictGenesis) {
		d.addFinding("missing_genesis", fmt.Sprintf("%s seq 0 does not start at genesis: %s", chain, formatChainRefs(genesisRefs)))
	}

	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			d.addFinding("chain_gap", fmt.Sprintf("%s missing seq %d before seq %d", chain, seqs[i-1]+1, seqs[i]))
			break
		}
	}

	for i := 1; i < len(seqs); i++ {
		prevSeq := seqs[i-1]
		seq := seqs[i]
		prevRefs := bySeq[prevSeq]
		curRefs := bySeq[seq]
		if len(prevRefs) != 1 || len(curRefs) != 1 {
			continue
		}
		if curRefs[0].PrevHash != prevRefs[0].Hash {
			d.addFinding("prev_hash_mismatch", fmt.Sprintf(
				"%s seq %d prev_hash %s does not match seq %d hash %s (%s -> %s)",
				chain, seq, shortDoctorHash(curRefs[0].PrevHash), prevSeq, shortDoctorHash(prevRefs[0].Hash), prevRefs[0].File, curRefs[0].File,
			))
		}
	}
}

func chainHasGenesis(refs []doctorChainRef, strict bool) bool {
	for _, ref := range refs {
		if ref.PrevHash == recorder.GenesisHash {
			return true
		}
		if !strict && strings.HasPrefix(ref.PrevHash, "g1:") {
			return true
		}
	}
	return false
}

func (d *evidenceDoctor) addFinding(kind, message string) {
	if len(d.findings) >= maxEvidenceDoctorFindings {
		d.truncated = true
		return
	}
	d.findings = append(d.findings, evidenceDoctorFinding{Kind: kind, Message: message})
}

func printEvidenceDoctorReport(cmd *cobra.Command, report evidenceDoctorReport) {
	out := cmd.OutOrStdout()

	verdict := "healthy"
	switch {
	case report.Damaged():
		verdict = "damaged"
	case !report.Conclusive():
		// Absence of findings over a partial scan is not health.
		verdict = "inconclusive"
	}
	_, _ = fmt.Fprintf(out, "evidence doctor: %s (%s, %d JSONL file(s) read)\n", verdict, report.Dir, report.FilesRead)
	if report.ScanTruncated {
		_, _ = fmt.Fprintf(out,
			"scan incomplete: skipped %d file(s) beyond the %d-file budget; absence of damage is NOT confirmed\n",
			report.FilesSkipped, maxEvidenceDoctorFiles)
	}
	if !report.Damaged() {
		return
	}

	// Summary first. On a badly forked directory the per-finding detail runs to
	// hundreds of lines, and an operator needs the shape before the specifics.
	counts := make(map[string]int, len(report.Findings))
	kinds := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		if _, seen := counts[finding.Kind]; !seen {
			kinds = append(kinds, finding.Kind)
		}
		counts[finding.Kind]++
	}
	sort.Strings(kinds)
	_, _ = fmt.Fprintf(out, "summary: %d finding(s) across %d kind(s)\n", len(report.Findings), len(kinds))
	for _, kind := range kinds {
		_, _ = fmt.Fprintf(out, "  %s: %d\n", kind, counts[kind])
	}

	_, _ = fmt.Fprintln(out, "details:")
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(out, "- %s: %s\n", finding.Kind, finding.Message)
	}
	if report.Truncated {
		_, _ = fmt.Fprintf(out, "- output_truncated: showing first %d findings; more damage exists\n", maxEvidenceDoctorFindings)
	}
}

// summarizeDoctorRefs renders at most maxDoctorRefsPerFinding references and
// states how many were omitted, so a finding stays readable without hiding that
// the real count is larger.
func summarizeDoctorRefs(parts []string) string {
	sort.Strings(parts)
	if len(parts) <= maxDoctorRefsPerFinding {
		return strings.Join(parts, "; ")
	}
	shown := parts[:maxDoctorRefsPerFinding]
	return fmt.Sprintf("%s; (and %d more)", strings.Join(shown, "; "), len(parts)-maxDoctorRefsPerFinding)
}

func isDoctorEvidenceJSONL(name string) bool {
	_, _, ok := parseDoctorEvidenceName(name, ".jsonl")
	return ok
}

func isDoctorRawSidecar(name string) bool {
	_, _, ok := parseDoctorEvidenceName(name, ".raw.enc")
	return ok
}

func parseDoctorEvidenceName(name, suffix string) (string, uint64, bool) {
	name = filepath.Base(name)
	if !strings.HasPrefix(name, "evidence-") || !strings.HasSuffix(name, suffix) {
		return "", 0, false
	}
	rest := strings.TrimPrefix(name, "evidence-")
	rest = strings.TrimSuffix(rest, suffix)
	lastDash := strings.LastIndex(rest, "-")
	if lastDash < 0 {
		return "", 0, false
	}
	seq, err := strconv.ParseUint(rest[lastDash+1:], 10, 64)
	if err != nil {
		return "", 0, false
	}
	sessionID := rest[:lastDash]
	if sessionID == "" {
		return "", 0, false
	}
	return sessionID, seq, true
}

func uniquePrevHashes(refs []doctorEntryRef) map[string]struct{} {
	out := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		out[ref.PrevHash] = struct{}{}
	}
	return out
}

func formatEntryRefs(refs []doctorEntryRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("%s seq=%d prev=%s hash=%s", ref.File, ref.Seq, shortDoctorHash(ref.PrevHash), shortDoctorHash(ref.Hash)))
	}
	return summarizeDoctorRefs(parts)
}

func formatChainRefs(refs []doctorChainRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		label := ref.Label
		if label == "" {
			label = "receipt"
		}
		parts = append(parts, fmt.Sprintf("%s %s seq=%d prev=%s hash=%s", ref.File, label, ref.Seq, shortDoctorHash(ref.PrevHash), shortDoctorHash(ref.Hash)))
	}
	return summarizeDoctorRefs(parts)
}

func shortDoctorHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
