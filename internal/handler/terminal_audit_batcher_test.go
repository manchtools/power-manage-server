package handler

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// recordingFlush collects every chunk the batcher emits so tests can
// assert ordering, sequence, and content.
type recordingFlush struct {
	mu     sync.Mutex
	chunks [][]byte
	seqs   []int64
}

func (r *recordingFlush) flush(data []byte, seq int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Copy: the batcher owns the buffer; we must not retain aliases.
	b := make([]byte, len(data))
	copy(b, data)
	r.chunks = append(r.chunks, b)
	r.seqs = append(r.seqs, seq)
}

func (r *recordingFlush) snapshot() ([][]byte, []int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs := make([][]byte, len(r.chunks))
	copy(cs, r.chunks)
	ss := make([]int64, len(r.seqs))
	copy(ss, r.seqs)
	return cs, ss
}

// waitForChunks polls until the batcher has emitted at least n flushes
// or timeout expires. Returns true if the target was reached.
func waitForChunks(r *recordingFlush, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		got := len(r.chunks)
		r.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestBatcher_SizeCapFlushesImmediately(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	defer b.Close()

	payload := bytes.Repeat([]byte("x"), terminalAuditFlushBytes)
	b.Write(payload)

	// Size cap should wake the flusher well under the debounce delay.
	if !waitForChunks(r, 1, terminalAuditFlushDelay/2) {
		t.Fatalf("size cap should flush before debounce elapses")
	}
	chunks, seqs := r.snapshot()
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], payload) {
		t.Errorf("chunk contents mismatch")
	}
	if seqs[0] != 1 {
		t.Errorf("first seq = %d, want 1", seqs[0])
	}
}

func TestBatcher_OversizedWriteSplitsAtCap(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	defer b.Close()

	// Single Write larger than the cap — representative of a paste
	// that arrives as one WebSocket frame. Must be split into
	// cap-sized chunks so no single audit event exceeds the cap.
	payload := bytes.Repeat([]byte("z"), terminalAuditFlushBytes*3+42)
	b.Write(payload)

	// Four flushes expected: three full caps + one 42-byte tail.
	if !waitForChunks(r, 4, terminalAuditFlushDelay+terminalAuditFlushDelay/2) {
		t.Fatalf("expected 4 chunks (3 full + 1 tail), timed out waiting")
	}
	chunks, seqs := r.snapshot()
	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d", len(chunks))
	}

	// Every chunk must respect the cap.
	for i, c := range chunks {
		if len(c) > terminalAuditFlushBytes {
			t.Errorf("chunk %d is %d bytes, exceeds cap %d", i, len(c), terminalAuditFlushBytes)
		}
	}
	// First three full, last is the tail remainder.
	if got, want := len(chunks[3]), 42; got != want {
		t.Errorf("tail chunk = %d bytes, want %d", got, want)
	}
	// Sequences must be strictly monotonic across the split, so
	// downstream consumers can reassemble in order.
	for i, seq := range seqs {
		if seq != int64(i+1) {
			t.Errorf("seqs[%d] = %d, want %d", i, seq, i+1)
		}
	}
	// Round-trip: concatenated chunks equal the input.
	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Errorf("reassembled payload does not match input (len got %d, want %d)", len(reassembled), len(payload))
	}
}

func TestBatcher_CoalescesKeystrokesIntoOneChunk(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	defer b.Close()

	// Simulate xterm.js sending one WS frame per keystroke.
	for _, c := range []byte("ls -la\n") {
		b.Write([]byte{c})
		// Tight loop — well inside the debounce window.
		time.Sleep(5 * time.Millisecond)
	}

	// Allow the debounce to expire.
	if !waitForChunks(r, 1, 2*terminalAuditFlushDelay) {
		t.Fatalf("expected a flush after debounce")
	}
	chunks, seqs := r.snapshot()
	if len(chunks) != 1 {
		t.Errorf("expected per-keystroke writes to coalesce into 1 chunk, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], []byte("ls -la\n")) {
		t.Errorf("coalesced content = %q, want %q", chunks[0], "ls -la\n")
	}
	if seqs[0] != 1 {
		t.Errorf("first seq should be 1, got %d", seqs[0])
	}
}

func TestBatcher_SequenceIsMonotonicAcrossFlushes(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	defer b.Close()

	// Three separated writes, each far enough apart that debounce
	// fires between them.
	b.Write([]byte("one"))
	time.Sleep(terminalAuditFlushDelay * 2)
	b.Write([]byte("two"))
	time.Sleep(terminalAuditFlushDelay * 2)
	b.Write([]byte("three"))

	if !waitForChunks(r, 3, 3*terminalAuditFlushDelay) {
		t.Fatalf("expected 3 flushes")
	}
	_, seqs := r.snapshot()
	for i, got := range seqs[:3] {
		want := int64(i + 1)
		if got != want {
			t.Errorf("seq[%d] = %d, want %d", i, got, want)
		}
	}
}

func TestBatcher_CloseFlushesPending(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)

	// Write far below the size cap and immediately close — the
	// debounce timer should NOT have had time to fire, but Close
	// must still flush the buffer so no bytes are lost.
	b.Write([]byte("unflushed"))
	b.Close()

	chunks, _ := r.snapshot()
	if len(chunks) != 1 {
		t.Fatalf("Close should flush pending, got %d chunks", len(chunks))
	}
	if !bytes.Equal(chunks[0], []byte("unflushed")) {
		t.Errorf("chunk = %q, want %q", chunks[0], "unflushed")
	}
}

func TestBatcher_CloseIsIdempotent(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	b.Write([]byte("x"))
	b.Close()
	b.Close() // must not panic or flush twice
	chunks, _ := r.snapshot()
	if len(chunks) != 1 {
		t.Errorf("double Close produced %d chunks, want 1", len(chunks))
	}
}

func TestBatcher_WriteAfterCloseIsNoop(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	b.Close()
	b.Write([]byte("late"))
	// Give any background goroutine a chance to (incorrectly) flush.
	time.Sleep(terminalAuditFlushDelay * 2)
	chunks, _ := r.snapshot()
	if len(chunks) != 0 {
		t.Errorf("write-after-close leaked %d chunks", len(chunks))
	}
}

func TestBatcher_EmptyWriteIsNoop(t *testing.T) {
	r := &recordingFlush{}
	b := newTerminalAuditBatcher(r.flush)
	defer b.Close()
	b.Write(nil)
	b.Write([]byte{})
	time.Sleep(terminalAuditFlushDelay * 2)
	chunks, _ := r.snapshot()
	if len(chunks) != 0 {
		t.Errorf("empty writes produced %d chunks, want 0", len(chunks))
	}
}
