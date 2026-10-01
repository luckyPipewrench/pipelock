// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestFragmentStorageReferenceParityAndSnapshots(t *testing.T) {
	var active, storage, reference []fragment
	var held, heldReference [][]fragment
	for step := range 20000 {
		next := fragment{data: []byte(fmt.Sprintf("body-%d", step)), at: time.Unix(int64(step), 0), sourceRequestID: []byte(fmt.Sprintf("request-%d", step))}
		active, storage = appendFragmentReusingStorage(active, storage, next)
		reference = append(reference, next)
		if step%113 == 0 {
			held = append(held, append([]fragment(nil), active...))
			heldReference = append(heldReference, append([]fragment(nil), reference...))
		}
		keep := 1 + step%31
		if len(active) > keep {
			active = active[len(active)-keep:]
			reference = reference[len(reference)-keep:]
		}
		if step%7 == 0 && len(active[0].data) > 1 {
			active[0].data = active[0].data[1:]
			reference[0].data = reference[0].data[1:]
		}
		if !reflect.DeepEqual(active, reference) {
			t.Fatalf("active descriptors differ at step %d", step)
		}
	}
	if !reflect.DeepEqual(held, heldReference) {
		t.Fatal("storage reuse mutated a held descriptor snapshot")
	}
}

func TestFragmentStorageReuseAndLargeTrim(t *testing.T) {
	storage := make([]fragment, 8)
	for i := range storage {
		storage[i] = fragment{data: []byte(fmt.Sprintf("body-%d", i))}
	}
	original := &storage[0]
	active := storage[3:]
	want := append(append([]fragment(nil), active...), fragment{data: []byte("next body")})
	active, storage = appendFragmentReusingStorage(active, storage, fragment{data: []byte("next body")})
	if &storage[0] != original || !reflect.DeepEqual(active, want) {
		t.Fatal("evicted capacity was not reused with identical active order")
	}
	for _, unused := range storage[len(active):] {
		if !reflect.DeepEqual(unused, fragment{}) {
			t.Fatal("compaction retained discarded descriptors")
		}
	}
	// Model a configuration reduction leaving one tail descriptor. Its next
	// append must release the historical larger allocation, like ordinary append.
	for len(active) < len(storage) {
		active, storage = appendFragmentReusingStorage(active, storage, fragment{data: []byte("fill tail")})
	}
	active = active[len(active)-1:]
	active, storage = appendFragmentReusingStorage(active, storage, fragment{data: []byte("after trim")})
	if &storage[0] == original || len(storage) > 4 || len(active) != 2 {
		t.Fatal("large trim retained historical backing capacity")
	}
}
