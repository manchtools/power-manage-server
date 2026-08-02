// Package archive stores integrity-sealed audit anchors and chain prefixes on
// the operator's off-host backup mount. Retention writes and verifies a prefix
// here before deleting any live audit row.
//
// Streaming by design (io.Reader / io.Writer, never []byte): a retained audit
// prefix can be large. The filesystem backend is the version-one backend.
package archive

import (
	"context"
	"errors"
	"io"
)

// Backend names the storage driver. The zero value is intentionally invalid so
// a misconfigured deployment fails loudly rather than silently defaulting.
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
// seal computed while the bytes stream in. Retention records that digest in
// the immutable audit checkpoint, so the archived object remains identifiable
// after its live prefix has been deleted.
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
