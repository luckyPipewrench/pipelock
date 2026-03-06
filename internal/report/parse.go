package report

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
)

// ParseOptions controls which events to include.
type ParseOptions struct {
	Since time.Time // include events at or after this time
	Until time.Time // include events before this time (zero = no limit)
}

// ParseResult contains parsed events and metadata about the parse.
type ParseResult struct {
	Events       []Event
	SkippedLines int // count of non-empty lines that failed JSON parsing
}

// ParseEvents reads newline-delimited JSON from r and returns parsed events
// sorted by timestamp. Malformed lines are counted (not silently dropped)
// so the report can surface data integrity issues.
func ParseEvents(r io.Reader, opts ParseOptions) (ParseResult, error) {
	var result ParseResult
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
			result.SkippedLines++
			continue
		}

		// Apply time filters.
		if !opts.Since.IsZero() && ev.Time.Before(opts.Since) {
			continue
		}
		if !opts.Until.IsZero() && !ev.Time.Before(opts.Until) {
			continue
		}

		result.Events = append(result.Events, ev)
	}

	if err := scanner.Err(); err != nil {
		// bufio.ErrTooLong means a single line exceeded the buffer.
		// Count it as a skipped line rather than aborting the whole report.
		if !errors.Is(err, bufio.ErrTooLong) {
			return ParseResult{}, err
		}
		result.SkippedLines++
	}

	sort.Slice(result.Events, func(i, j int) bool {
		return result.Events[i].Time.Before(result.Events[j].Time)
	})

	return result, nil
}
