// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tornTailMetricStub struct {
	path   string
	offset int64
}

func (*tornTailMetricStub) RecordEmitFailure(string) {}

func (s *tornTailMetricStub) RecordEvidenceTornTail(path string, offset int64) {
	s.path, s.offset = path, offset
}

func TestTornTailRestartPreservesShard(t *testing.T) {
	for _, damage := range []string{"nul", "truncated", "missing_newline"} {
		t.Run(damage, func(t *testing.T) {
			dir := t.TempDir()
			_, key := generateTestKey(t)
			first := startRun(t, dir, key)
			first.openAndEmit(t, 1)
			first.close(t)
			files, err := filepath.Glob(filepath.Join(dir, "evidence-"+first.session+"-*.jsonl"))
			if err != nil || len(files) != 1 {
				t.Fatalf("files=%v err=%v", files, err)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "nul":
				data = append(data, 0, 0)
			case "truncated":
				data = append(data, []byte(`{"v":`)...)
			case "missing_newline":
				data = bytes.TrimSuffix(data, []byte("\n"))
			}
			if err := os.WriteFile(files[0], data, 0o600); err != nil {
				t.Fatal(err)
			}
			before := sha256.Sum256(data)
			second := startRun(t, dir, key)
			defer second.close(t)
			m := &tornTailMetricStub{}
			second.e.metrics = m
			var notices bytes.Buffer
			second.e.notices = &notices
			second.openAndEmit(t, 1)
			if m.path != files[0] || m.offset < 0 {
				t.Fatalf("missing predecessor torn observation: %+v", m)
			}
			if second.session == first.session || second.e.ChainLink() != nil {
				t.Fatal("torn predecessor adopted")
			}
			if !strings.Contains(notices.String(), "not linked") || !strings.Contains(notices.String(), "torn JSONL tail") {
				t.Fatalf("missing discontinuity notice: %s", notices.String())
			}
			if len(sessionReceipts(t, dir, second.session)) != 2 {
				t.Fatal("fresh run receipts missing")
			}
			after, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if sha256.Sum256(after) != before {
				t.Fatal("restart modified damaged predecessor")
			}
		})
	}
}
