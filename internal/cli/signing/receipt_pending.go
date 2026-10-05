// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// pendingCheckpoint is a signed checkpoint whose only remaining candidate
// signer is the next receipt's key.
type pendingCheckpoint struct {
	index    int
	seq      uint64
	prevHash string
	sig      []byte
}

// pendingInMemory is how many waiting checkpoints stay in memory before the
// rest are written to the spill file. At a few hundred bytes each that is a
// fixed fraction of a megabyte, whatever the recorder's length.
const pendingInMemory = 1024

// maxPendingCheckpoints is the most signed checkpoints one receipt gap may
// hold. A gap cannot hold more checkpoints than a session has entries, and
// the evidence readers stop a session at this many entries, so an honest
// recorder never reaches it, whatever its checkpoint interval.
const maxPendingCheckpoints = recorder.MaxEvidenceReadDirectoryEntries * recorder.MaxEvidenceReadEntries

// pendingSpillHeader is index, sequence, and the two field lengths.
const pendingSpillHeader = 8 + 8 + 4 + 4

var (
	errTooManyPendingCheckpoints = fmt.Errorf("more than %d signed checkpoints wait for the next receipt's signer, more than a session within the evidence read limits holds; a writer signs that many only with flight_recorder.checkpoint_interval set low and no receipt for that long, so raise checkpoint_interval", maxPendingCheckpoints)
	errPendingSpillChanged       = errors.New("signed checkpoints held for the next receipt's signer were changed on disk before they were verified")
)

// pendingCheckpoints holds the signed checkpoints of one receipt gap that
// wait for the next receipt's signer. The first pendingInMemory stay in
// memory; the rest go to an unlinked private temporary file and are read back
// when the gap settles, so an honest recorder that signs a checkpoint after
// every entry verifies in bounded memory. Every byte written is hashed and
// the read-back must hash the same, so a spill file changed while it was held
// fails verification instead of being trusted.
type pendingCheckpoints struct {
	mem []pendingCheckpoint

	file *os.File
	// name is set while the spill file still has a directory entry, on a
	// platform that cannot remove an open file.
	name    string
	w       *bufio.Writer
	written hash.Hash
	size    int64
	spilled int
	// firstSpilled is the entry index of the first spilled checkpoint.
	firstSpilled int
	// maxField is the longest field written, so a read-back that names a
	// longer one is refused before it allocates.
	maxField uint32
}

// len reports how many checkpoints are waiting.
func (p *pendingCheckpoints) len() int { return len(p.mem) + p.spilled }

// add holds c until the gap settles. An error means c could not be held and
// verification must fail.
func (p *pendingCheckpoints) add(c pendingCheckpoint) error {
	if len(p.mem) < pendingInMemory {
		p.mem = append(p.mem, c)
		return nil
	}
	ph, phOK := spillLength(len(c.prevHash))
	sl, slOK := spillLength(len(c.sig))
	if !phOK || !slOK || c.index < 0 {
		return errors.New("checkpoint field out of range")
	}
	if p.file == nil {
		if err := p.open(); err != nil {
			return err
		}
	}
	if p.spilled == 0 {
		p.firstSpilled = c.index
	}
	var hdr [pendingSpillHeader]byte
	binary.BigEndian.PutUint64(hdr[0:], uint64(c.index))
	binary.BigEndian.PutUint64(hdr[8:], c.seq)
	binary.BigEndian.PutUint32(hdr[16:], ph)
	binary.BigEndian.PutUint32(hdr[20:], sl)
	p.maxField = max(p.maxField, ph, sl)
	w := io.MultiWriter(p.w, p.written)
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("writing spill file: %w", err)
	}
	if _, err := io.WriteString(w, c.prevHash); err != nil {
		return fmt.Errorf("writing spill file: %w", err)
	}
	if _, err := w.Write(c.sig); err != nil {
		return fmt.Errorf("writing spill file: %w", err)
	}
	p.size += int64(pendingSpillHeader) + int64(ph) + int64(sl)
	p.spilled++
	return nil
}

// spillLength converts a field length to the spill file's width.
func spillLength(n int) (uint32, bool) {
	if n < 0 || n > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

func (p *pendingCheckpoints) open() error {
	f, err := os.CreateTemp("", "pipelock-verify-checkpoints-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file for checkpoints waiting on the next receipt's signer (set TMPDIR to a writable directory): %w", err)
	}
	// Unlink at once where the platform allows it, so nothing is left
	// behind and nothing else can open the file by name.
	if os.Remove(f.Name()) != nil {
		p.name = f.Name()
	}
	p.file = f
	p.w = bufio.NewWriterSize(f, 64<<10)
	p.written = sha256.New()
	return nil
}

// drain hands every waiting checkpoint to fn, in order, and empties the
// store. An error means the spilled checkpoints could not be read back
// exactly as written; fn may have seen some of them, and verification must
// fail.
func (p *pendingCheckpoints) drain(fn func(pendingCheckpoint)) error {
	for _, c := range p.mem {
		fn(c)
	}
	clear(p.mem)
	p.mem = p.mem[:0]
	if p.spilled == 0 {
		return nil
	}
	n, size, maxField := p.spilled, p.size, p.maxField
	want := p.written.Sum(nil)
	p.spilled, p.size, p.maxField = 0, 0, 0
	p.written.Reset()
	if err := p.w.Flush(); err != nil {
		return fmt.Errorf("writing spill file: %w", err)
	}
	got := sha256.New()
	r := bufio.NewReaderSize(io.TeeReader(io.NewSectionReader(p.file, 0, size), got), 64<<10)
	var hdr [pendingSpillHeader]byte
	for range n {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return fmt.Errorf("%w: %w", errPendingSpillChanged, err)
		}
		index := binary.BigEndian.Uint64(hdr[0:])
		ph, sl := binary.BigEndian.Uint32(hdr[16:]), binary.BigEndian.Uint32(hdr[20:])
		if index > math.MaxInt || ph > maxField || sl > maxField {
			return errPendingSpillChanged
		}
		field := make([]byte, int(ph)+int(sl))
		if _, err := io.ReadFull(r, field); err != nil {
			return fmt.Errorf("%w: %w", errPendingSpillChanged, err)
		}
		fn(pendingCheckpoint{
			index:    int(index),
			seq:      binary.BigEndian.Uint64(hdr[8:]),
			prevHash: string(field[:ph]),
			sig:      field[ph:],
		})
	}
	if !bytes.Equal(got.Sum(nil), want) {
		return errPendingSpillChanged
	}
	// Reuse the file for the next gap.
	if err := p.file.Truncate(0); err != nil {
		return fmt.Errorf("resetting spill file: %w", err)
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("resetting spill file: %w", err)
	}
	p.w.Reset(p.file)
	return nil
}

// close releases the spill file. It is safe to call more than once and on a
// store that never spilled.
func (p *pendingCheckpoints) close() {
	if p.file == nil {
		return
	}
	_ = p.file.Close()
	if p.name != "" {
		_ = os.Remove(p.name)
	}
	p.file, p.name, p.w = nil, "", nil
	p.mem = nil
	p.spilled, p.size = 0, 0
}
