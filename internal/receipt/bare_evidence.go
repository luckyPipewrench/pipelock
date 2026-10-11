// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// IsBareEvidenceSession recognizes only receipt-only compatibility input. Any
// recorder metadata or mixed entry requires full recorder chain verification.
func IsBareEvidenceSession(location recorder.EvidenceLocation, session string) (bool, error) {
	notBare := errors.New("not a bare evidence receipt session")
	seen := false
	err := recorder.WalkSessionHistoryFiles(location, session, func(_ recorder.SessionHistoryShard, r io.Reader) error {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(line, &fields) != nil || len(fields) != 2 || fields["detail"] == nil {
				return notBare
			}
			var kind string
			if json.Unmarshal(fields["type"], &kind) != nil || kind != contractreceipt.EvidenceEntryType {
				return notBare
			}
			seen = true
		}
		return scanner.Err()
	})
	if errors.Is(err, notBare) {
		return false, nil
	}
	return seen && err == nil, err
}
