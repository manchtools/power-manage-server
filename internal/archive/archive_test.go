package archive_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/archive"
)

// Spec 19 AC 23 — the ArchiveStore streams artifacts to/from the
// operator-configured path via io.Reader/io.Writer; the zero/unknown
// backend is rejected (ErrUnknownBackend). AC 22 — integrity seal:
// tampering with any archived byte is detected.

func fsStore(t *testing.T) archive.ArchiveStore {
	t.Helper()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: t.TempDir()})
	require.NoError(t, err)
	return st
}

func TestNew_UnknownBackendRejected(t *testing.T) {
	_, err := archive.New(archive.Config{Backend: "s3-someday", FilesystemPath: t.TempDir()})
	require.ErrorIs(t, err, archive.ErrUnknownBackend)

	// Zero backend is also rejected — no silent default.
	_, err = archive.New(archive.Config{})
	require.ErrorIs(t, err, archive.ErrUnknownBackend)
}

func TestNew_FilesystemRequiresWritablePath(t *testing.T) {
	_, err := archive.New(archive.Config{Backend: archive.BackendFilesystem})
	require.Error(t, err, "fs backend needs a path")

	_, err = archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: "/nonexistent/definitely/not/writable"})
	require.Error(t, err, "fs backend needs a writable path")
}

func TestFilesystem_PutGetRoundTrip(t *testing.T) {
	st := fsStore(t)
	ctx := context.Background()
	payload := bytes.Repeat([]byte("archive-bytes-"), 5000) // multi-KB, exercises streaming

	info, err := st.Put(ctx, "prune-000001", bytes.NewReader(payload))
	require.NoError(t, err)
	assert.Equal(t, "prune-000001", info.Ref)
	assert.Equal(t, int64(len(payload)), info.Size)
	assert.NotEmpty(t, info.SHA256, "Put computes the integrity seal while streaming")

	rc, err := st.Get(ctx, "prune-000001")
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, payload, got, "Get streams the exact bytes back")
}

func TestFilesystem_PutIsAtomic_NoPartialOnGet(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	_, err = st.Put(ctx, "atomic-1", strings.NewReader("hello world"))
	require.NoError(t, err)

	// No temp/partial files linger in the archive dir (atomic rename).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".tmp", "no temp file may linger after an atomic Put")
	}
}

func TestFilesystem_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	info, err := st.Put(ctx, "sealed-1", strings.NewReader("the original sealed contents"))
	require.NoError(t, err)

	// Verify passes on the pristine artifact.
	require.NoError(t, archive.Verify(ctx, st, "sealed-1"))

	// Flip a byte in the stored archive file.
	target := filepath.Join(dir, "sealed-1")
	if _, statErr := os.Stat(target); statErr != nil {
		// backend may suffix the ref; find the data file.
		target = findArchiveFile(t, dir, "sealed-1")
	}
	raw, err := os.ReadFile(target)
	require.NoError(t, err)
	raw[len(raw)/2] ^= 0xFF
	require.NoError(t, os.WriteFile(target, raw, 0o600))

	// The seal now fails — tampering with any archived byte is detected.
	err = archive.Verify(ctx, st, "sealed-1")
	require.Error(t, err, "a flipped byte must break the integrity seal (AC 22)")

	// The reported sha is the hash of the untampered original (recorded
	// out of band by the prune event), so a re-hash of the flipped bytes
	// mismatches it — the seal is what the prune event pins.
	want := sha256.Sum256([]byte("the original sealed contents"))
	assert.Equal(t, hex.EncodeToString(want[:]), info.SHA256)
}

func TestFilesystem_List(t *testing.T) {
	st := fsStore(t)
	ctx := context.Background()
	_, err := st.Put(ctx, "a-0001", strings.NewReader("one"))
	require.NoError(t, err)
	_, err = st.Put(ctx, "a-0002", strings.NewReader("two"))
	require.NoError(t, err)

	infos, err := st.List(ctx)
	require.NoError(t, err)
	refs := map[string]bool{}
	for _, i := range infos {
		refs[i.Ref] = true
		assert.NotEmpty(t, i.SHA256)
	}
	assert.True(t, refs["a-0001"] && refs["a-0002"], "List reports every archived artifact")
}

// findArchiveFile locates the data file for a ref when the backend
// stores it under a suffixed name.
func findArchiveFile(t *testing.T, dir, ref string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ref) && !strings.HasSuffix(e.Name(), ".sha256") {
			return filepath.Join(dir, e.Name())
		}
	}
	t.Fatalf("archive file for %q not found in %s", ref, dir)
	return ""
}

// TestFilesystem_RejectsReservedRefNamespaces pins the CR-flagged gap:
// a ref colliding with the backend's own naming (seal suffix, temp
// infix, probe prefix) is rejected, not silently mis-stored.
func TestFilesystem_RejectsReservedRefNamespaces(t *testing.T) {
	st := fsStore(t)
	ctx := context.Background()
	for _, ref := range []string{"x.sha256", "a.tmp-1", ".pm-archive-probe-9", "..", "a/b", ""} {
		_, err := st.Put(ctx, ref, strings.NewReader("data"))
		assert.Error(t, err, "reserved/unsafe ref %q must be rejected", ref)
	}
}

// TestFilesystem_List_UnreadableSealDoesNotHideOthers pins the CR
// resilience fix: a missing/unreadable seal marks THAT entry
// (SHA256 == "") rather than failing the whole List and hiding every
// safely-archived artifact.
func TestFilesystem_List_UnreadableSealDoesNotHideOthers(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	_, err = st.Put(ctx, "good-1", strings.NewReader("good"))
	require.NoError(t, err)
	_, err = st.Put(ctx, "bad-1", strings.NewReader("bad"))
	require.NoError(t, err)

	// Remove one artifact's seal — simulating the fsync-gap / tamper case.
	require.NoError(t, os.Remove(filepath.Join(dir, "bad-1.sha256")))

	infos, err := st.List(ctx)
	require.NoError(t, err, "List must not fail wholesale on one bad seal")
	byRef := map[string]string{}
	for _, i := range infos {
		byRef[i.Ref] = i.SHA256
	}
	assert.NotEmpty(t, byRef["good-1"], "the good artifact keeps its seal")
	sha, listed := byRef["bad-1"]
	assert.True(t, listed, "the seal-less artifact is still surfaced")
	assert.Empty(t, sha, "its missing seal shows as SHA256==\"\"")
}
