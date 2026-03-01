package wsutil

import (
	"testing"

	"github.com/gobwas/ws"
)

func TestFragmentState_SingleFrame(t *testing.T) {
	f := &FragmentState{MaxBytes: 1024}
	payload := []byte("hello")
	hdr := ws.Header{Fin: true, OpCode: ws.OpText, Length: int64(len(payload))}

	complete, msg, closeCode, _ := f.Process(hdr, payload)
	if !complete {
		t.Fatal("expected complete message")
	}
	if string(msg) != "hello" {
		t.Errorf("expected %q, got %q", "hello", string(msg))
	}
	if closeCode != 0 {
		t.Errorf("expected no close code, got %d", closeCode)
	}
	if f.Opcode != ws.OpText {
		t.Errorf("expected opcode text, got %d", f.Opcode)
	}
}

func TestFragmentState_FragmentedMessage(t *testing.T) {
	f := &FragmentState{MaxBytes: 1024}

	// First fragment (non-FIN).
	hdr1 := ws.Header{Fin: false, OpCode: ws.OpText, Length: 5}
	complete, _, closeCode, _ := f.Process(hdr1, []byte("hello"))
	if complete {
		t.Fatal("expected incomplete after first fragment")
	}
	if closeCode != 0 {
		t.Fatalf("unexpected close code: %d", closeCode)
	}
	if !f.Active {
		t.Fatal("expected active fragment state")
	}

	// Continuation (FIN).
	hdr2 := ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 6}
	complete, msg, closeCode, _ := f.Process(hdr2, []byte(" world"))
	if !complete {
		t.Fatal("expected complete after final continuation")
	}
	if string(msg) != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", string(msg))
	}
	if closeCode != 0 {
		t.Errorf("unexpected close code: %d", closeCode)
	}
}

func TestFragmentState_OversizedSingleFrame(t *testing.T) {
	f := &FragmentState{MaxBytes: 5}
	payload := []byte("toolong")
	hdr := ws.Header{Fin: true, OpCode: ws.OpText, Length: int64(len(payload))}

	complete, _, closeCode, reason := f.Process(hdr, payload)
	if complete {
		t.Fatal("expected incomplete for oversized frame")
	}
	if closeCode != ws.StatusMessageTooBig {
		t.Errorf("expected StatusMessageTooBig, got %d", closeCode)
	}
	if reason != ReasonMessageTooLarge {
		t.Errorf("expected reason %q, got %q", ReasonMessageTooLarge, reason)
	}
}

func TestFragmentState_OversizedFragmentedMessage(t *testing.T) {
	f := &FragmentState{MaxBytes: 8}

	// First fragment fits.
	hdr1 := ws.Header{Fin: false, OpCode: ws.OpText, Length: 5}
	complete, _, closeCode, _ := f.Process(hdr1, []byte("hello"))
	if complete || closeCode != 0 {
		t.Fatal("first fragment should be accepted")
	}

	// Continuation exceeds limit.
	hdr2 := ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 6}
	complete, _, closeCode, _ = f.Process(hdr2, []byte(" world"))
	if complete {
		t.Fatal("expected incomplete for oversized continuation")
	}
	if closeCode != ws.StatusMessageTooBig {
		t.Errorf("expected StatusMessageTooBig, got %d", closeCode)
	}
}

func TestFragmentState_UnexpectedContinuation(t *testing.T) {
	f := &FragmentState{MaxBytes: 1024}
	hdr := ws.Header{Fin: true, OpCode: ws.OpContinuation, Length: 5}

	_, _, closeCode, _ := f.Process(hdr, []byte("hello"))
	if closeCode != ws.StatusProtocolError {
		t.Errorf("expected StatusProtocolError, got %d", closeCode)
	}
}

func TestFragmentState_NewDataDuringFragmentation(t *testing.T) {
	f := &FragmentState{MaxBytes: 1024}

	// Start fragment.
	hdr1 := ws.Header{Fin: false, OpCode: ws.OpText, Length: 5}
	f.Process(hdr1, []byte("hello"))

	// New data frame (not continuation) while fragmentation active.
	hdr2 := ws.Header{Fin: true, OpCode: ws.OpText, Length: 5}
	_, _, closeCode, _ := f.Process(hdr2, []byte("world"))
	if closeCode != ws.StatusProtocolError {
		t.Errorf("expected StatusProtocolError, got %d", closeCode)
	}
}

func TestFragmentState_Reset(t *testing.T) {
	f := &FragmentState{MaxBytes: 1024}

	// Start a fragment.
	hdr := ws.Header{Fin: false, OpCode: ws.OpText, Length: 5}
	f.Process(hdr, []byte("hello"))
	if !f.Active {
		t.Fatal("expected active after fragment start")
	}

	f.Reset()
	if f.Active {
		t.Error("expected inactive after reset")
	}
	if f.Opcode != 0 {
		t.Error("expected zero opcode after reset")
	}
}

func TestFragmentState_OversizedFirstFragment(t *testing.T) {
	f := &FragmentState{MaxBytes: 3}
	hdr := ws.Header{Fin: false, OpCode: ws.OpText, Length: 10}

	_, _, closeCode, _ := f.Process(hdr, []byte("toolongfragment"))
	if closeCode != ws.StatusMessageTooBig {
		t.Errorf("expected StatusMessageTooBig, got %d", closeCode)
	}
}
