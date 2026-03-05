package report

import (
	"bufio"
	"encoding/json"
	"io"
	"sort"
	"time"
)

// ParseOptions controls which events to include.
type ParseOptions struct {
	Since time.Time // include events at or after this time
	Until time.Time // include events before this time (zero = no limit)
}

// ParseEvents reads newline-delimited JSON from r and returns parsed events
// sorted by timestamp. Lines that fail to parse are silently skipped.
func ParseEvents(r io.Reader, opts ParseOptions) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)

	// 1 MiB max line size to handle verbose audit entries safely.
	const maxLineSize = 1 << 20
	scanner.Buffer(make([]byte, 0, maxLineSize), maxLineSize)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // malformed lines silently skipped
		}

		// Apply time filters.
		if !opts.Since.IsZero() && ev.Time.Before(opts.Since) {
			continue
		}
		if !opts.Until.IsZero() && !ev.Time.Before(opts.Until) {
			continue
		}

		events = append(events, ev)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Time.Before(events[j].Time)
	})

	return events, nil
}
