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

// ArchiveStore streams artifacts to/from the operator-configured path via
// io.Reader/io.Writer; an unknown backend is rejected and tampering with any
// archived byte is detected.

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

// TestFilesystem_CorruptionDetected covers the accident, not the attack: a
// storage fault flips bytes in the artifact and leaves everything else alone.
func TestFilesystem_CorruptionDetected(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	info, err := st.Put(ctx, "sealed-1", strings.NewReader("the original sealed contents"))
	require.NoError(t, err)

	// Put's digest is computed from the bytes as they stream in, so it is
	// what retention records durably in audit_chain_checkpoints.
	want := sha256.Sum256([]byte("the original sealed contents"))
	require.Equal(t, hex.EncodeToString(want[:]), info.SHA256)

	// Verify passes on the pristine artifact.
	require.NoError(t, archive.Verify(ctx, st, "sealed-1", info.SHA256))

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

	assert.Error(t, archive.Verify(ctx, st, "sealed-1", info.SHA256),
		"a flipped byte must not rehash to the digest retention recorded")
}

// TestFilesystem_TamperDetectedAgainstTheDurableDigest is the case the archive
// exists for. The sidecar sits in the same directory as the artifact under the
// same permissions, so whoever can rewrite one can rewrite both — comparing
// them proves only that the attacker was consistent. Verification must rest on
// the digest recorded outside the archive, in the append-only
// audit_chain_checkpoints.archive_digest that authorised deleting the live rows.
func TestFilesystem_TamperDetectedAgainstTheDurableDigest(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	info, err := st.Put(ctx, "sealed-1", strings.NewReader("the original sealed contents"))
	require.NoError(t, err)
	durable := info.SHA256 // the value retention writes to the checkpoint row

	// Rewrite the artifact AND its sidecar together, consistently: the
	// archive mount is now internally coherent and describes a document that
	// was never archived.
	forged := []byte("the contents an attacker would rather the auditor read")
	forgedSum := sha256.Sum256(forged)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sealed-1"), forged, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sealed-1.sha256"),
		[]byte(hex.EncodeToString(forgedSum[:])), 0o600))

	require.NotEqual(t, durable, hex.EncodeToString(forgedSum[:]),
		"matches-zero guard: the forged bytes must actually differ from the archived ones")
	assert.Error(t, archive.Verify(ctx, st, "sealed-1", durable),
		"a consistently rewritten artifact and sidecar must still fail against the durable digest")

	// Control: read the expected value back out of the archive, exactly as
	// the defective version did, and the forgery verifies. The mount is
	// internally coherent, so only a digest held outside it can expose the
	// substitution — which is why Verify takes one as an argument.
	sidecar := readSidecar(t, dir, "sealed-1")
	require.Equal(t, hex.EncodeToString(forgedSum[:]), sidecar,
		"the attacker's sidecar describes the attacker's artifact")
	require.NoError(t, archive.Verify(ctx, st, "sealed-1", sidecar),
		"a self-referential comparison cannot detect a consistent forgery")

	// The sidecar List reports is that same attacker-controlled claim, so
	// sourcing the expected digest from List is the same defect.
	infos, err := st.List(ctx)
	require.NoError(t, err)
	var listed string
	for _, info := range infos {
		if info.Ref == "sealed-1" {
			listed = info.SHA256
		}
	}
	require.Equal(t, sidecar, listed, "List reports the archive's own claim about the artifact")
}

// readSidecar returns the digest the archive stores beside an artifact.
func readSidecar(t *testing.T, dir, ref string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, ref+".sha256"))
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

// TestVerify_RefusesWithoutADurableDigest keeps the check from degrading into
// a no-op: a caller with nothing durable to compare against has performed no
// verification, and must be told so rather than handed a nil error.
func TestVerify_RefusesWithoutADurableDigest(t *testing.T) {
	dir := t.TempDir()
	st, err := archive.New(archive.Config{Backend: archive.BackendFilesystem, FilesystemPath: dir})
	require.NoError(t, err)
	ctx := context.Background()

	info, err := st.Put(ctx, "sealed-1", strings.NewReader("the original sealed contents"))
	require.NoError(t, err)

	unusable := map[string]string{
		"empty":           "",
		"truncated":       info.SHA256[:32],
		"over-long":       info.SHA256 + "00",
		"not hexadecimal": strings.Repeat("z", 64),
	}
	require.NotEmpty(t, unusable, "matches-zero guard: the unusable-digest table is empty")
	for name, expected := range unusable {
		assert.Error(t, archive.Verify(ctx, st, "sealed-1", expected),
			"%s: an unusable digest is not a verification", name)
	}

	// The pristine artifact still verifies, so the refusals above are about
	// the digest and not about the artifact.
	assert.NoError(t, archive.Verify(ctx, st, "sealed-1", info.SHA256))
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
