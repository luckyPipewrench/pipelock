package scanner

import "testing"

func TestAppendNovelSegments_SuppressesRepeatedSegments(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, 60)
	defer fb.Close()

	seg := func(parts ...string) [][]byte {
		out := make([][]byte, 0, len(parts))
		for _, p := range parts {
			out = append(out, []byte(p))
		}
		return out
	}

	fb.AppendNovelSegments(testSessionA, seg("upload", "part1"))
	afterFirst := fb.TotalBufferBytes()
	if afterFirst != len("uploadpart1") {
		t.Fatalf("first append buffered %d bytes, want %d", afterFirst, len("uploadpart1"))
	}

	// The repeated route segment must not be stored again, so it cannot sit
	// between the two payload halves and break DLP contiguity.
	fb.AppendNovelSegments(testSessionA, seg("upload", "part2"))
	if got, want := fb.TotalBufferBytes(), len("uploadpart1part2"); got != want {
		t.Fatalf("second append buffered %d bytes, want %d", got, want)
	}

	// A wholly repeated path adds nothing at all.
	fb.AppendNovelSegments(testSessionA, seg("upload", "part1"))
	if got, want := fb.TotalBufferBytes(), len("uploadpart1part2"); got != want {
		t.Fatalf("repeated path buffered %d bytes, want %d", got, want)
	}
}

func TestAppendNovelSegments_EmptyInputs(t *testing.T) {
	fb := NewFragmentBuffer(4096, 10, 60)
	defer fb.Close()

	if res := fb.AppendNovelSegments(testSessionA, nil); res.CapacityExceeded {
		t.Error("nil segments should be a no-op")
	}
	if res := fb.AppendNovelSegments(testSessionA, [][]byte{{}, nil}); res.CapacityExceeded {
		t.Error("empty segments should be a no-op")
	}
	if got := fb.TotalBufferBytes(); got != 0 {
		t.Errorf("buffered %d bytes from empty input, want 0", got)
	}
}

func TestAppendNovelSegments_RefusesNewSessionAtCap(t *testing.T) {
	fb := NewFragmentBuffer(4096, 1, 60)
	defer fb.Close()

	fb.AppendNovelSegments(testSessionA, [][]byte{[]byte("first")})
	res := fb.AppendNovelSegments(testSessionB, [][]byte{[]byte("second")})
	if !res.CapacityExceeded {
		t.Error("expected CapacityExceeded once the session cap is reached")
	}
}
