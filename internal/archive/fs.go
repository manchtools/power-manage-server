package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// sealSuffix names the sidecar holding an artifact's integrity seal
// (the hex sha256 of the data file). Kept beside the artifact so the
// archive is self-verifying offline (AC 22) without the live system.
const sealSuffix = ".sha256"

// probePrefix names the writability-probe temp files newFilesystem
// creates; refs may not collide with it (nor with sealSuffix / the
// temp infix — see refPath).
const probePrefix = ".pm-archive-probe-"

// filesystem is the v1 ArchiveStore backend: one directory of sealed
// artifacts on operator-configured storage (the deployment runs it on
// encrypted disk — see the spec's deployment requirement).
type filesystem struct {
	dir string
}

// newFilesystem validates the path is an existing writable directory —
// a retention-enable with an unwritable path must fail loudly at
// configuration time, not at the first prune.
func newFilesystem(dir string) (*filesystem, error) {
	if dir == "" {
		return nil, errors.New("archive: filesystem backend requires a path")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("archive: filesystem path %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("archive: filesystem path %q is not a directory", dir)
	}
	// Probe writability with a temp file so a read-only mount fails now.
	probe, err := os.CreateTemp(dir, probePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("archive: filesystem path %q not writable: %w", dir, err)
	}
	probeName := probe.Name()
	probe.Close()
	_ = os.Remove(probeName)
	return &filesystem{dir: dir}, nil
}

// refPath rejects a ref that would escape the archive directory (path
// traversal): refs are prune checkpoints minted internally, but a
// backend must never trust a ref to compose a path unchecked.
func (f *filesystem) refPath(ref string) (string, error) {
	if ref == "" || strings.ContainsAny(ref, `/\`) || strings.Contains(ref, "..") ||
		strings.HasSuffix(ref, sealSuffix) || strings.Contains(ref, ".tmp-") ||
		strings.HasPrefix(ref, probePrefix) {
		// Also reject refs that collide with the backend's own naming
		// namespaces — a ref ending in .sha256 / containing .tmp- / with
		// the probe prefix would be silently skipped by List or mistaken
		// for a seal, so an operator would believe data was never
		// archived (CR).
		return "", fmt.Errorf("archive: invalid ref %q", ref)
	}
	return filepath.Join(f.dir, ref), nil
}

// writeFileSync writes data to path and fsyncs the FILE contents before
// returning — os.WriteFile does not, so a seal could be empty/truncated
// after power loss even though the dir entry survives, which would fail
// a fully-archived ref's later verification (CR).
func writeFileSync(path string, data []byte) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// syncDir fsyncs the archive directory so a rename or newly-created
// sidecar survives a crash. Load-bearing: the archive is the ONLY copy
// of the events the prune step subsequently deletes — a rename that
// isn't durable is silent data loss on power-loss (CR).
func (f *filesystem) syncDir() error {
	d, err := os.Open(f.dir)
	if err != nil {
		return fmt.Errorf("archive: open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("archive: fsync dir: %w", err)
	}
	return nil
}

func (f *filesystem) Put(ctx context.Context, ref string, r io.Reader) (ArchiveInfo, error) {
	dst, err := f.refPath(ref)
	if err != nil {
		return ArchiveInfo{}, err
	}

	// Stream into a temp file in the SAME directory (so the final rename
	// is atomic on one filesystem), hashing as we go.
	tmp, err := os.CreateTemp(f.dir, ref+".tmp-*")
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("archive: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	defer func() { _ = os.Remove(tmpName) }()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		return ArchiveInfo{}, fmt.Errorf("archive: stream %s: %w", ref, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ArchiveInfo{}, fmt.Errorf("archive: fsync %s: %w", ref, err)
	}
	if err := tmp.Close(); err != nil {
		return ArchiveInfo{}, fmt.Errorf("archive: close %s: %w", ref, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	// Write the seal sidecar first (fsync'd — the bytes, not just the
	// dir entry, must survive power loss, else a fully-archived ref
	// fails verification later), then atomically publish the data file:
	// Get/List only see a ref whose data is fully written, and a present
	// data file always has its durable seal.
	if err := writeFileSync(dst+sealSuffix, []byte(sum)); err != nil {
		return ArchiveInfo{}, fmt.Errorf("archive: write seal %s: %w", ref, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(dst + sealSuffix)
		return ArchiveInfo{}, fmt.Errorf("archive: publish %s: %w", ref, err)
	}
	// fsync the directory so the seal-file creation AND the rename are
	// durable before we report success — the caller (prune worker) only
	// deletes events after a durable archive lands (AC 28).
	if err := f.syncDir(); err != nil {
		return ArchiveInfo{}, err
	}
	return ArchiveInfo{Ref: ref, Size: n, SHA256: sum}, nil
}

func (f *filesystem) Get(ctx context.Context, ref string) (io.ReadCloser, error) {
	p, err := f.refPath(ref)
	if err != nil {
		return nil, err
	}
	rc, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("archive: open %s: %w", ref, err)
	}
	return rc, nil
}

func (f *filesystem) List(ctx context.Context) ([]ArchiveInfo, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, fmt.Errorf("archive: list: %w", err)
	}
	var out []ArchiveInfo
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, sealSuffix) || strings.Contains(name, ".tmp-") || strings.HasPrefix(name, probePrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("archive: stat %s: %w", name, err)
		}
		// An unreadable/missing seal marks THAT entry (SHA256 == "")
		// rather than failing the whole List — during an incident an
		// operator most needs to see what IS safely archived. Verify is
		// the authoritative per-artifact integrity check.
		seal, err := os.ReadFile(filepath.Join(f.dir, name+sealSuffix))
		if err != nil {
			out = append(out, ArchiveInfo{Ref: name, Size: info.Size(), SHA256: ""})
			continue
		}
		out = append(out, ArchiveInfo{Ref: name, Size: info.Size(), SHA256: strings.TrimSpace(string(seal))})
	}
	return out, nil
}

// Verify recomputes an artifact's hash from its stored bytes and
// compares it to its seal — tamper detection independent of the live
// system (AC 22). A mismatch, a missing artifact, or a missing seal is
// an error.
func Verify(ctx context.Context, store ArchiveStore, ref string) error {
	fs, ok := store.(*filesystem)
	if !ok {
		return errors.New("archive: Verify supports the filesystem backend only")
	}
	p, err := fs.refPath(ref)
	if err != nil {
		return err
	}
	seal, err := os.ReadFile(p + sealSuffix)
	if err != nil {
		return fmt.Errorf("archive: read seal for %s: %w", ref, err)
	}
	rc, err := fs.Get(ctx, ref)
	if err != nil {
		return err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return fmt.Errorf("archive: rehash %s: %w", ref, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.TrimSpace(string(seal)) {
		return fmt.Errorf("archive: integrity seal MISMATCH for %s — the artifact has been tampered with", ref)
	}
	return nil
}
