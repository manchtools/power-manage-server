// Package archive is the pluggable cold-storage backend for pruned
// event-log history (spec 19 retention). The prune worker writes each
// {snapshot, events ≤ N} artifact through an ArchiveStore as one
// integrity-sealed, independently-replayable blob BEFORE any event is
// deleted from the live log.
//
// Streaming by design (io.Reader / io.Writer, never []byte): a prune of
// months of events can be large, and freezing the slice shape would
// force an interface break when the S3-compatible backend lands. The
// filesystem backend is v1; a second backend adds here without any
// prune-worker change (AC 23).
package archive

import (
	"context"
	"errors"
	"io"
)

// Backend names the storage driver. The zero value is intentionally
// invalid so a mis-configured deployment fails loudly rather than
// silently defaulting somewhere (AC 23).
type Backend string

const (
	// BackendFilesystem writes artifacts to an operator-configured
	// directory (v1).
	BackendFilesystem Backend = "filesystem"
)

// ErrUnknownBackend is returned by New for the zero value or any
// backend the build does not implement.
var ErrUnknownBackend = errors.New("archive: unknown storage backend")

// Config selects and configures a backend.
type Config struct {
	Backend        Backend
	FilesystemPath string // required when Backend == BackendFilesystem
}

// ArchiveInfo describes one stored artifact. SHA256 is the integrity
// seal computed while the bytes stream in; the prune worker also
// records it in the EventLogPruned event so the seal is checkable both
// against the archive (offline) and against the tamper-evident log.
type ArchiveInfo struct {
	Ref    string
	Size   int64
	SHA256 string
}

// ArchiveStore is the streaming cold-archive interface. Implementations
// must make Put atomic (a reader/crash mid-write must never leave a
// half-written artifact visible to Get/List).
type ArchiveStore interface {
	// Put streams r to the artifact named ref, sealing it, and returns
	// its ArchiveInfo. Atomic: the artifact is visible only once fully
	// written and sealed.
	Put(ctx context.Context, ref string, r io.Reader) (ArchiveInfo, error)
	// Get opens the artifact named ref for streaming read.
	Get(ctx context.Context, ref string) (io.ReadCloser, error)
	// List returns every stored artifact's info.
	List(ctx context.Context) ([]ArchiveInfo, error)
}

// New constructs the configured backend. The zero/unknown backend is
// rejected with ErrUnknownBackend — no silent default.
func New(cfg Config) (ArchiveStore, error) {
	switch cfg.Backend {
	case BackendFilesystem:
		return newFilesystem(cfg.FilesystemPath)
	default:
		return nil, ErrUnknownBackend
	}
}
