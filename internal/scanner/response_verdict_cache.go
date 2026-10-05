// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"hash"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	responseVerdictMaxEntries = 64
	responseVerdictMaxBytes   = 16 << 20
	responseVerdictMaxBody    = 4 << 20
)

type responseVerdictKey struct {
	body     [32]byte
	revision [32]byte
	suppress [32]byte
}

type responseVerdictEntry struct {
	key    responseVerdictKey
	size   int
	result ResponseScanResult
}

// The byte budget counts source bytes represented by entries, even though the
// cache stores only digests. This also bounds the work admitted per entry.
type responseVerdictCache struct {
	mu       sync.Mutex
	revision [32]byte
	entries  map[responseVerdictKey]*list.Element
	order    list.List
	bytes    int
	flights  map[responseVerdictKey]*responseVerdictFlight
}

func (c *responseVerdictCache) key(body []byte, target string, suppress []config.SuppressEntry) (responseVerdictKey, bool) {
	if len(body) > responseVerdictMaxBody {
		return responseVerdictKey{}, false
	}
	h := sha256.New()
	writeCacheField(h, target)
	for _, entry := range suppress {
		writeCacheField(h, entry.Rule)
		writeCacheField(h, entry.Path)
		writeCacheField(h, entry.Reason)
	}
	var suppression [32]byte
	copy(suppression[:], h.Sum(nil))
	return responseVerdictKey{body: sha256.Sum256(body), revision: c.revision, suppress: suppression}, true
}

func writeCacheField(h hash.Hash, value string) {
	// JSON string quoting plus a terminator gives each field an unambiguous frame.
	encoded, _ := json.Marshal(value)
	_, _ = h.Write(encoded)
	_, _ = h.Write([]byte{0})
}

func (c *responseVerdictCache) get(key responseVerdictKey) (ResponseScanResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element := c.entries[key]; element != nil {
		c.order.MoveToFront(element)
		return element.Value.(responseVerdictEntry).result, true
	}
	return ResponseScanResult{}, false
}

func (c *responseVerdictCache) put(key responseVerdictKey, size int, result ResponseScanResult) {
	// A suppressed or observed finding is evidence, even when the verdict is clean.
	// It must be produced again for every request and can depend on time.
	if size < 0 || size > responseVerdictMaxBody || !result.Clean || result.Failed() || len(result.Matches) != 0 ||
		len(result.SuppressedMatches) != 0 || len(result.ObservedCoreMatches) != 0 || result.TransformedContent != "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[responseVerdictKey]*list.Element)
	}
	if existing := c.entries[key]; existing != nil {
		c.order.MoveToFront(existing)
		return
	}
	// Prefer retaining larger represented bodies, whose full scans cost more.
	// Recency breaks size ties; a new entry is always admitted within the bounds.
	for len(c.entries) >= responseVerdictMaxEntries || c.bytes+size > responseVerdictMaxBytes {
		victim := c.order.Back()
		for el := victim.Prev(); el != nil; el = el.Prev() {
			if el.Value.(responseVerdictEntry).size < victim.Value.(responseVerdictEntry).size {
				victim = el
			}
		}
		entry := victim.Value.(responseVerdictEntry)
		delete(c.entries, entry.key)
		c.bytes -= entry.size
		c.order.Remove(victim)
	}
	c.entries[key] = c.order.PushFront(responseVerdictEntry{key: key, size: size, result: result})
	c.bytes += size
}

func (s *Scanner) responsePatternRevision() [32]byte {
	h := sha256.New()
	writeCacheField(h, s.responseAction)
	if s.responseEnabled {
		writeCacheField(h, "enabled")
	}
	sets := [][]*compiledPattern{
		s.responsePatterns, s.responseOptSpacePatterns, s.responseVowelFoldPatterns,
		s.core.responsePatterns, s.core.responseOptSpacePatterns, s.core.responseVowelFoldPatterns,
	}
	for i, patterns := range sets {
		writeCacheField(h, string(rune('0'+i)))
		for _, p := range patterns {
			writeCacheField(h, p.name)
			writeCacheField(h, p.re.String()) // includes inline regexp flags
			writeCacheField(h, p.severity)
			if p.warn {
				writeCacheField(h, "warn")
			}
			if p.withoutLeftBoundary != nil {
				writeCacheField(h, p.withoutLeftBoundary.String())
			}
		}
	}
	var revision [32]byte
	copy(revision[:], h.Sum(nil))
	return revision
}

// Flights signal cache publication only. Nonordinary results are never shared.
type responseVerdictFlight struct{ done chan struct{} }

func (c *responseVerdictCache) beginFlight(key responseVerdictKey) (*responseVerdictFlight, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if flight := c.flights[key]; flight != nil {
		return flight, false
	}
	if len(c.flights) >= responseVerdictMaxEntries {
		return nil, false
	}
	if c.flights == nil {
		c.flights = make(map[responseVerdictKey]*responseVerdictFlight)
	}
	flight := &responseVerdictFlight{done: make(chan struct{})}
	c.flights[key] = flight
	return flight, true
}

func (c *responseVerdictCache) endFlight(key responseVerdictKey, flight *responseVerdictFlight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.flights, key)
	close(flight.done)
}
