// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// HeadTrustedVerifier verifies a complete chain against an out-of-band live
// head signer. No summary is released until every signature, hash link,
// rotation boundary and lifecycle rule verifies and the final signer matches.
// A successor's signed transition authenticates its predecessor, so verifying
// all boundaries forward and pinning the final key gives the same trust as a
// backward walk from that key. This is not trust-on-first-use or endorsement
// verification and must only be used by callers that trust the live head.
//
// Memory holds one segment, a bounded lifecycle cache and the ordered unique
// signer keys required by the checkpoint. Repeated rotations do not retain
// segment history; large lifecycle histories spill to private temporary files.
// Close must be called to remove any temporary state.
type HeadTrustedVerifier struct {
	v           *chainVerifier
	headKey     string
	prefixCount uint64
	count       uint64
	start       time.Time
	end         time.Time
	finalSeq    uint64
	prefix      ChainResult
	err         error
}

func NewHeadTrustedVerifier(headKey string, prefixCount uint64) (*HeadTrustedVerifier, error) {
	if headKey == "" {
		return nil, errors.New("refuse auto-anchor: live receipt emitter signer key is unavailable")
	}
	return &HeadTrustedVerifier{
		v:       &chainVerifier{trusted: make(map[string]struct{}), compact: true, runStore: &boundedRunStore{}},
		headKey: headKey, prefixCount: prefixCount,
	}, nil
}

// Add verifies a receipt without retaining it. Intermediate keys are only
// candidates until Finish pins the live head; an error permanently fails the walk.
func (s *HeadTrustedVerifier) Add(r Receipt) error {
	if s.err != nil {
		return s.err
	}
	// Keep only the current candidate in the walking core's trust set. The
	// core still verifies the actual prior signer at each rotation boundary.
	clear(s.v.trusted)
	s.v.trusted[r.SignerKey] = struct{}{}
	if res, ok := s.v.add(r, s.count); !ok {
		s.err = fmt.Errorf("invalid receipt chain: %s", res.Error)
		return s.err
	}
	if s.count == 0 {
		s.start = r.ActionRecord.Timestamp
	}
	s.count++
	s.end = r.ActionRecord.Timestamp
	s.finalSeq = r.ActionRecord.ChainSeq
	if s.count == s.prefixCount {
		s.prefix = s.summary()
	}
	return nil
}

func (s *HeadTrustedVerifier) summary() ChainResult {
	return ChainResult{
		Valid: true, IntegrityVerified: true, ReceiptCount: s.count,
		FinalSeq: s.finalSeq, RootHash: s.v.prevHash, StartTime: s.start, EndTime: s.end,
		SignerKeys: append([]string(nil), s.v.signerKeys...),
	}
}

// Finish returns the full summary and, if requested, a verified prefix summary.
// The prefix is authenticated by the fully verified path to the live head too.
func (s *HeadTrustedVerifier) Finish() (ChainResult, ChainResult, error) {
	if s.err != nil {
		return ChainResult{}, ChainResult{}, s.err
	}
	if s.count == 0 {
		return ChainResult{}, ChainResult{}, errors.New("refuse auto-anchor: live receipt chain is empty")
	}
	if s.v.curKey != s.headKey {
		return ChainResult{}, ChainResult{}, fmt.Errorf("refuse auto-anchor: receipt chain head signer %q does not match live emitter signer", s.v.curKey)
	}
	if s.prefixCount > s.count {
		return ChainResult{}, ChainResult{}, fmt.Errorf("auto-anchor checkpoint receipt_count %d is ahead of live chain count %d", s.prefixCount, s.count)
	}
	if err := s.v.runStore.verify(); err != nil {
		s.err = fmt.Errorf("verify session lifecycle state: %w", err)
		return ChainResult{}, ChainResult{}, s.err
	}
	return s.summary(), s.prefix, nil
}

func (s *HeadTrustedVerifier) Close() error {
	return s.v.runStore.close()
}

// Lifecycle replay detection needs every past run identity, even after close.
// Cache a small number and spill rather than weakening duplicate-open detection.
const runCacheLimit = 64

type storedRun struct {
	Run    string
	Open   string
	Closed bool
}

type boundedRunStore struct {
	cache map[string]storedRun
	dir   string
	key   [32]byte
	root  [32]byte
	files uint64
}

type diskRun struct {
	Record json.RawMessage
	MAC    []byte
}

func (v *chainVerifier) readRun(run string) (string, bool, bool, error) {
	if v.runStore != nil {
		return v.runStore.read(run)
	}
	open, ok := v.runNonces[run]
	return open, v.closedRuns[run], ok, nil
}

func (v *chainVerifier) writeRun(run, open string, closed bool) error {
	if v.runStore != nil {
		return v.runStore.write(storedRun{Run: run, Open: open, Closed: closed})
	}
	v.runNonces[run] = open
	v.closedRuns[run] = closed
	return nil
}

func (s *boundedRunStore) path(run string) string {
	h := sha256.Sum256([]byte(run))
	return filepath.Join(s.dir, hex.EncodeToString(h[:]))
}

func (s *boundedRunStore) read(run string) (string, bool, bool, error) {
	if r, ok := s.cache[run]; ok {
		return r.Open, r.Closed, true, nil
	}
	if s.dir == "" {
		return "", false, false, nil
	}
	r, _, found, err := s.scan(run)
	if err != nil {
		return "", false, false, err
	}
	if found {
		s.remember(r)
	}
	return r.Open, r.Closed, found, nil
}

func (s *boundedRunStore) write(r storedRun) error {
	if s.cache == nil {
		s.cache = make(map[string]storedRun)
	}
	if s.dir == "" && (len(s.cache) < runCacheLimit || s.cache[r.Run].Run != "") {
		s.cache[r.Run] = r
		return nil
	}
	if s.dir == "" {
		if _, err := rand.Read(s.key[:]); err != nil {
			return err
		}
		sweepStaleSpillDirs(os.TempDir(), time.Now())
		dir, err := os.MkdirTemp("", spillDirPrefix)
		if err != nil {
			return err
		}
		s.dir = dir
		cachedRuns := s.cache
		s.cache = make(map[string]storedRun)
		for _, cached := range cachedRuns {
			if err := s.persist(cached); err != nil {
				return err
			}
		}
	}
	return s.persist(r)
}

func (s *boundedRunStore) persist(r storedRun) error {
	record, err := json.Marshal(r)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write(record)
	raw, err := json.Marshal(diskRun{Record: record, MAC: mac.Sum(nil)})
	if err != nil {
		return err
	}
	_, old, _, err := s.scan(r.Run)
	if err != nil {
		return err
	}
	if err := writeSpillFile(s.dir, s.path(r.Run), raw); err != nil {
		return err
	}
	if old == nil {
		s.files++
	} else {
		s.xorHash(old)
	}
	s.xorHash(raw)
	s.remember(r)
	return nil
}

func (s *boundedRunStore) xorHash(raw []byte) {
	hash := sha256.Sum256(raw)
	for i := range s.root {
		s.root[i] ^= hash[i]
	}
}

func (s *boundedRunStore) load(path string) (storedRun, []byte, error) {
	// The run/open identity bytes came from one bounded recorder entry. Keep
	// scratch reads bounded too, including JSON escaping and MAC framing.
	raw, err := recorder.ReadEvidenceFileBounded(path, 2*recorder.MaxEntryLineBytes+1024)
	if err != nil {
		return storedRun{}, nil, err
	}
	var disk diskRun
	if err := json.Unmarshal(raw, &disk); err != nil {
		return storedRun{}, nil, err
	}
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write(disk.Record)
	if !hmac.Equal(mac.Sum(nil), disk.MAC) {
		return storedRun{}, nil, errors.New("session lifecycle state authentication failed")
	}
	var r storedRun
	if err := json.Unmarshal(disk.Record, &r); err != nil {
		return storedRun{}, nil, err
	}
	if path != s.path(r.Run) {
		return storedRun{}, nil, errors.New("session lifecycle state identity mismatch")
	}
	return r, raw, nil
}

// Authenticate every lookup, then audit the disk set before releasing a
// summary. The in-memory count and multiset digest detect removed/replaced
// identities too: an absent spill file must not hide a duplicate session_open.
// Directory enumeration is batched so the audit retains no lifecycle history.
func (s *boundedRunStore) verify() error {
	_, _, _, err := s.scan("")
	return err
}

// A cache miss is answered only from a complete authenticated set snapshot.
// MAC alone is insufficient: an older authentic record could otherwise roll a
// closed run back to open between lookups. Hold only the matching record while
// verifying the count/digest, then release its value to the lifecycle verifier.
func (s *boundedRunStore) scan(run string) (storedRun, []byte, bool, error) {
	if s.dir == "" {
		return storedRun{}, nil, false, nil
	}
	dir, err := os.Open(filepath.Clean(s.dir))
	if err != nil {
		return storedRun{}, nil, false, err
	}
	defer func() { _ = dir.Close() }()
	var root [32]byte
	var count uint64
	var match storedRun
	var matchedBytes []byte
	for {
		entries, readErr := dir.ReadDir(1)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return storedRun{}, nil, false, readErr
		}
		for _, entry := range entries {
			r, raw, err := s.load(filepath.Join(s.dir, entry.Name()))
			if err != nil {
				return storedRun{}, nil, false, err
			}
			hash := sha256.Sum256(raw)
			for i := range root {
				root[i] ^= hash[i]
			}
			count++
			if r.Run == run {
				match, matchedBytes = r, raw
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if count != s.files || root != s.root {
		return storedRun{}, nil, false, errors.New("session lifecycle state set changed")
	}
	return match, matchedBytes, matchedBytes != nil, nil
}

func (s *boundedRunStore) remember(r storedRun) {
	if s.cache == nil {
		s.cache = make(map[string]storedRun)
	}
	if _, exists := s.cache[r.Run]; !exists && len(s.cache) >= runCacheLimit {
		for run := range s.cache {
			delete(s.cache, run)
			break
		}
	}
	s.cache[r.Run] = r
}

func (s *boundedRunStore) close() error {
	if s.dir == "" {
		return nil
	}
	return os.RemoveAll(s.dir)
}

const (
	spillDirPrefix = "pipelock-chain-runs-"
	// A walk refreshes its spill directory's mtime on every write, so a
	// directory untouched this long belongs to a killed process.
	staleSpillAge = 24 * time.Hour
)

// writeSpillFile writes through a fresh exclusively created file and renames
// it into place. Rename replaces a planted symlink instead of following it, so
// a same-user race cannot redirect the write to another file.
func writeSpillFile(dir, path string, raw []byte) error {
	f, err := os.CreateTemp(dir, ".spill-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// sweepStaleSpillDirs removes spill directories left by killed processes. It
// is best effort: directories it cannot remove (another user's, in a sticky
// temp directory) are left alone.
func sweepStaleSpillDirs(root string, now time.Time) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), spillDirPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < staleSpillAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, e.Name()))
	}
}
