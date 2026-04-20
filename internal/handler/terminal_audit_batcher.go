package handler

import (
	"sync"
	"time"
)

// Terminal audit batcher tunables. Picked to coalesce typical shell
// input (a typed command plus brief reading/thinking pauses) into one
// event without producing noticeable audit latency:
//
//   - 4 KiB cap: well above a typed command line; still bounded so a
//     paste of a script body flushes mid-stream instead of ballooning
//     the event payload.
//   - 1 s debounce: flush only after typing pauses for a full second,
//     so a command with micro-pauses (e.g. reading a path mid-type)
//     coalesces into one audit event. Audit latency up to the same
//     1 s, which is imperceptible for a tailing operator and bounds
//     the data at risk on a hard gateway crash to roughly one second
//     of keystrokes (~100 bytes typical). Clean session close always
//     flushes the pending buffer regardless.
const (
	terminalAuditFlushBytes = 4096
	terminalAuditFlushDelay = 1 * time.Second
)

// auditFlush is the callback the batcher invokes to persist a buffered
// chunk. The batcher guarantees data is non-empty, seq is strictly
// monotonic (1-based), and flush runs synchronously — so the caller
// can update its own state without extra locking.
type auditFlush func(data []byte, seq int64)

// terminalAuditBatcher coalesces per-keystroke stdin chunks into
// meaningful audit events. Earlier versions enqueued one chunk per
// WebSocket frame, which — because xterm.js sends one frame per
// keystroke — produced one event per character. At 50+ chars/command
// it flooded the event store with opaque single-byte base64 blobs.
//
// A batcher instance is owned by a single bridge session. Call Write
// from the WS→agent read loop; call Close from the same goroutine's
// defer once reading is done. The batcher runs one background flush
// goroutine that respects both the size cap and the debounce timer.
type terminalAuditBatcher struct {
	flush auditFlush

	mu     sync.Mutex
	buf    []byte
	seq    int64
	closed bool
	// timerC is a channel the flush goroutine waits on when the
	// buffer is non-empty. Rearming it from Write is cheap because
	// time.AfterFunc reuses a per-timer goroutine internally.
	timer *time.Timer
	// woken is signalled when either the buffer crosses the size
	// threshold or a close happens, so the flush loop doesn't need
	// to poll.
	woken chan struct{}
	done  chan struct{}
}

func newTerminalAuditBatcher(flush auditFlush) *terminalAuditBatcher {
	b := &terminalAuditBatcher{
		flush: flush,
		woken: make(chan struct{}, 1),
		done:  make(chan struct{}),
	}
	go b.run()
	return b
}

// Write appends data to the pending buffer. Oversized buffers wake
// the flush goroutine immediately; otherwise the flush timer is
// (re)armed so quiet periods produce a flush after the debounce.
func (b *terminalAuditBatcher) Write(data []byte) {
	if len(data) == 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.buf = append(b.buf, data...)
	needImmediate := len(b.buf) >= terminalAuditFlushBytes
	if b.timer == nil {
		b.timer = time.AfterFunc(terminalAuditFlushDelay, b.wake)
	} else {
		// Debounce: reset timer so a steady stream of keystrokes
		// does not flush until typing pauses (or the size cap
		// triggers an immediate flush).
		b.timer.Reset(terminalAuditFlushDelay)
	}
	b.mu.Unlock()
	if needImmediate {
		b.wake()
	}
}

// Close flushes any pending buffer and tears down the flush
// goroutine. Safe to call from a defer — further Writes are no-ops.
func (b *terminalAuditBatcher) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	b.wake()
	<-b.done
}

func (b *terminalAuditBatcher) wake() {
	select {
	case b.woken <- struct{}{}:
	default:
	}
}

// run is the single flush goroutine. It sleeps on `woken` and emits
// one flush per wake cycle if the buffer is non-empty. Exits when
// Close has been called AND the buffer is empty.
func (b *terminalAuditBatcher) run() {
	defer close(b.done)
	for {
		<-b.woken
		b.mu.Lock()
		data := b.buf
		b.buf = nil
		closed := b.closed
		b.mu.Unlock()
		if len(data) > 0 {
			b.mu.Lock()
			b.seq++
			seq := b.seq
			b.mu.Unlock()
			b.flush(data, seq)
		}
		if closed {
			// Drain: if Close raced with an in-flight Write, a
			// final buffer may have been appended after we read
			// it above. Flush that too so no bytes are lost.
			b.mu.Lock()
			tail := b.buf
			b.buf = nil
			b.mu.Unlock()
			if len(tail) > 0 {
				b.mu.Lock()
				b.seq++
				seq := b.seq
				b.mu.Unlock()
				b.flush(tail, seq)
			}
			return
		}
	}
}
