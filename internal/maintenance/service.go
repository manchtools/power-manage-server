// Package maintenance wires the fixed control-plane housekeeping jobs to the
// durable SQLite scheduler.
package maintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/backupstatus"
	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/webhook"
)

const (
	KindAuditVerify      = "audit.verify"
	KindAuditAnchor      = "audit.anchor"
	KindAuditRetention   = "audit.retention"
	KindAuthStateCleanup = "identity.auth_state_cleanup"
	KindBackupInspect    = "storage.backup_inspect"
	KindSecurityInspect  = "security.inspect"

	auditVerifyInterval      = time.Hour
	auditAnchorInterval      = 15 * time.Minute
	auditRetentionInterval   = 24 * time.Hour
	authStateCleanupInterval = time.Hour
	securityInspectInterval  = 15 * time.Minute
	backupInspectInterval    = 15 * time.Minute
	maintenanceMaxAttempts   = int32(100)
	maxAnchorBytes           = 4 << 10
	externalAnchorRef        = "audit-anchor-control-latest.json"
)

var recurring = map[string]time.Duration{
	KindAuditVerify:      auditVerifyInterval,
	KindAuditAnchor:      auditAnchorInterval,
	KindAuditRetention:   auditRetentionInterval,
	KindAuthStateCleanup: authStateCleanupInterval,
	KindBackupInspect:    backupInspectInterval,
	KindSecurityInspect:  securityInspectInterval,
}

// Notifier is the only outbound notification capability maintenance needs.
type Notifier interface {
	Send(context.Context, webhook.Event) error
}

// Config supplies the fixed maintenance dependencies and operator retention
// policy.
type Config struct {
	Store        *store.Store
	Archive      archive.ArchiveStore
	Retention    time.Duration
	Now          func() time.Time
	Notifier     Notifier
	BackupPath   string
	BackupMaxLag time.Duration
}

// Service implements the production maintenance job handlers.
type Service struct {
	store        *store.Store
	archive      archive.ArchiveStore
	retention    time.Duration
	now          func() time.Time
	notifier     Notifier
	backupPath   string
	backupMaxLag time.Duration
}

// New constructs the maintenance service.
func New(cfg Config) *Service {
	if cfg.Store == nil || cfg.Archive == nil || cfg.Retention <= 0 || cfg.BackupPath == "" || cfg.BackupMaxLag <= 0 {
		panic("maintenance: store, archive, backup policy, and positive retention are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{
		store: cfg.Store, archive: cfg.Archive, retention: cfg.Retention,
		now: cfg.Now, notifier: cfg.Notifier,
		backupPath: cfg.BackupPath, backupMaxLag: cfg.BackupMaxLag,
	}
}

// Handlers returns the complete fixed job registry.
func (s *Service) Handlers() map[string]jobs.Handler {
	return map[string]jobs.Handler{
		KindAuditVerify:      s.VerifyAudit,
		KindAuditAnchor:      s.AnchorAudit,
		KindAuditRetention:   s.RetainAudit,
		KindAuthStateCleanup: s.CleanupAuthStates,
		KindBackupInspect:    s.InspectBackup,
		KindSecurityInspect:  s.InspectSecurity,
	}
}

// Recurring returns the fixed schedule used by the durable runner.
func (s *Service) Recurring() map[string]time.Duration {
	out := make(map[string]time.Duration, len(recurring))
	for kind, interval := range recurring {
		out[kind] = interval
	}
	return out
}

// EnsureScheduled seeds one durable singleton per maintenance kind. Existing
// pending or claimed rows survive restarts and are left untouched.
func (s *Service) EnsureScheduled(ctx context.Context) error {
	if ctx == nil {
		return errors.New("maintenance scheduling requires a context")
	}
	kinds := make([]string, 0, len(recurring))
	for kind := range recurring {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		if _, err := s.store.GetLiveJobByDedupe(ctx, kind); err == nil {
			continue
		} else if !store.IsNotFound(err) {
			return err
		}
		opID := ulid.Make().String()
		op := backgroundOperation(opID, "maintenance.schedule."+kind)
		_, err := s.store.WithAudit(ctx, op, func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			_, err := jobs.InsertInTx(ctx, tx, rec, jobs.InsertParams{
				OperationID: opID, Kind: kind, Payload: json.RawMessage(`{}`), DueAt: s.now().UTC(),
				MaxAttempts: maintenanceMaxAttempts, DedupeKey: kind,
			})
			return err
		})
		if err != nil {
			return fmt.Errorf("schedule %s: %w", kind, err)
		}
	}
	return nil
}

// VerifyAudit checks the local chain against the durable evidence that is
// supposed to exist outside it, and fails closed whenever that evidence is
// gone.
//
// "Nothing has ever been anchored" is legitimate — it is what a fresh
// deployment looks like — and is the only case in which the pass proceeds
// without an expected anchor. Once an anchor row exists, this database has
// asserted that a chain position was published somewhere it does not control;
// if that object is missing, the assertion cannot be checked. Reporting
// success there would make a chain proven intact indistinguishable from one
// whose off-host evidence has been destroyed, which is the failure an auditor
// is relying on this job to catch.
func (s *Service) VerifyAudit(ctx context.Context, _ jobs.Job) error {
	opts := store.AuditVerifyOptions{CheckStoredAnchors: true}

	// Look for the object this database recorded as published, and fall back
	// to the fixed publication name when it recorded none — an anchor written
	// just before a crash, before its row landed, is still evidence and the
	// chain still has to reproduce it.
	ref, recorded := externalAnchorRef, false
	published, err := s.store.LatestAuditAnchor(ctx, store.DefaultAuditStream)
	switch {
	case err == nil:
		ref, recorded = published.ExternalRef, true
	case store.IsNotFound(err):
		// Nothing has ever been anchored. Nothing can be missing.
	default:
		return err
	}

	external, found, err := s.externalAnchor(ctx, ref)
	if err != nil {
		return err
	}
	switch {
	case recorded && !found:
		return fmt.Errorf(
			"audit anchor %q is recorded as published at chain position %d but is absent from the archive: "+
				"the off-host anchor has been lost or removed and the chain can no longer be verified against it",
			ref, published.ChainSeq)
	case recorded && found && contradicts(external, published):
		return fmt.Errorf(
			"archived audit anchor %q (stream %q, chain position %d) contradicts the anchor recorded for it "+
				"(stream %q, chain position %d): the off-host anchor has been rolled back or rewritten",
			ref, external.Stream, external.ChainSeq, published.Stream, published.ChainSeq)
	case found:
		opts.ExpectedAnchor = &store.AuditAnchor{
			AnchorID: external.Ref, Stream: external.Stream,
			ChainSeq: external.ChainSeq, RowHash: external.RowHash,
		}
	}

	if err := s.requireArchivedPrefixes(ctx); err != nil {
		return err
	}
	_, err = s.store.VerifyAuditChain(ctx, opts)
	return err
}

// contradicts reports whether an archived anchor disagrees with the anchor row
// recorded for it.
//
// Running AHEAD is not a contradiction: publishing writes the object first and
// records the row second, so a crash in between leaves a newer object that the
// next anchor pass adopts, and the chain still has to reproduce it. Running
// behind, or carrying a different hash at the same position, means the object
// was rolled back or rewritten.
func contradicts(external externalAnchor, published store.AuditAnchor) bool {
	return external.Stream != published.Stream ||
		external.ChainSeq < published.ChainSeq ||
		(external.ChainSeq == published.ChainSeq && !bytes.Equal(external.RowHash, published.RowHash))
}

// requireArchivedPrefixes fails closed when a retention checkpoint names an
// archived prefix the archive no longer holds. Those live rows were deleted on
// the strength of that object, so its absence is destroyed evidence and not a
// bookkeeping discrepancy.
//
// Presence only. Re-hashing every retained prefix costs the whole archive on
// every pass; that check belongs to the retention job, which pays it once a
// day and only in order to earn the right to delete more.
func (s *Service) requireArchivedPrefixes(ctx context.Context) error {
	checkpoints, err := s.store.ListAuditCheckpoints(ctx, store.DefaultAuditStream)
	if err != nil {
		return err
	}
	if len(checkpoints) == 0 {
		return nil
	}
	infos, err := s.archive.List(ctx)
	if err != nil {
		return fmt.Errorf("list audit archive: %w", err)
	}
	present := make(map[string]struct{}, len(infos))
	for _, info := range infos {
		present[info.Ref] = struct{}{}
	}
	for _, checkpoint := range checkpoints {
		if _, ok := present[checkpoint.ArchiveRef]; !ok {
			return fmt.Errorf(
				"archived audit prefix %q for checkpoint %s (boundary %d) is absent from the archive: "+
					"the audit rows it covers were deleted on the strength of that object",
				checkpoint.ArchiveRef, checkpoint.CheckpointID, checkpoint.BoundarySeq)
		}
	}
	return nil
}

// verifyArchivedPrefixes re-hashes every retained prefix and compares it with
// the digest its checkpoint recorded. That digest is the durable copy: the
// checkpoint table is append-only and lives in the database, not on the
// archive mount, so it is the one value an attacker who owns the mount cannot
// bring into agreement with a substituted artifact.
func (s *Service) verifyArchivedPrefixes(ctx context.Context) error {
	checkpoints, err := s.store.ListAuditCheckpoints(ctx, store.DefaultAuditStream)
	if err != nil {
		return err
	}
	for _, checkpoint := range checkpoints {
		if err := archive.Verify(ctx, s.archive, checkpoint.ArchiveRef, checkpoint.ArchiveDigest); err != nil {
			return fmt.Errorf("verify archived audit prefix for checkpoint %s (boundary %d): %w",
				checkpoint.CheckpointID, checkpoint.BoundarySeq, err)
		}
	}
	return nil
}

// AnchorAudit verifies the current chain, writes its tip to the configured
// off-host archive, verifies the stored object, then records the publication.
func (s *Service) AnchorAudit(ctx context.Context, _ jobs.Job) error {
	if err := s.VerifyAudit(ctx, jobs.Job{}); err != nil {
		return err
	}
	tip, err := s.store.AuditChainTipOf(ctx, store.DefaultAuditStream)
	if err != nil || tip.Height == 0 {
		return err
	}
	external, found, err := s.externalAnchor(ctx, externalAnchorRef)
	if err != nil {
		return err
	}
	if found && external.ChainSeq == tip.Height && bytes.Equal(external.RowHash, tip.HeadHash) {
		latest, localErr := s.store.LatestAuditAnchor(ctx, tip.Stream)
		if localErr == nil && latest.ChainSeq == tip.Height && bytes.Equal(latest.RowHash, tip.HeadHash) {
			return nil
		}
		if localErr != nil && !store.IsNotFound(localErr) {
			return localErr
		}
		_, err = s.store.RecordPublishedAuditAnchor(ctx, tip, external.Ref)
		return err
	}

	ref := externalAnchorRef
	payload, err := json.Marshal(externalAnchorFile{
		Version: 1, Stream: tip.Stream, ChainSeq: tip.Height,
		RowHashHex: hex.EncodeToString(tip.HeadHash), CapturedAt: s.now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal audit anchor: %w", err)
	}
	payload = append(payload, '\n')
	info, err := s.archive.Put(ctx, ref, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("publish audit anchor: %w", err)
	}
	// Read the object back against the digest computed from the bytes that
	// went out, which is held here in memory and never on the archive mount.
	if err := archive.Verify(ctx, s.archive, ref, info.SHA256); err != nil {
		return fmt.Errorf("verify published audit anchor: %w", err)
	}
	_, err = s.store.RecordPublishedAuditAnchor(ctx, tip, ref)
	return err
}

// RetainAudit anchors the current chain, archives the newest closed prefix
// older than policy, verifies the archived object, and only then prunes it.
func (s *Service) RetainAudit(ctx context.Context, _ jobs.Job) error {
	if err := s.AnchorAudit(ctx, jobs.Job{}); err != nil {
		return err
	}
	// Earn the right to delete more evidence: every prefix already archived
	// must still hash to the digest its checkpoint recorded. Retention is the
	// one job that destroys live audit rows, so it is where the full re-hash
	// of the archive is worth its cost — and refusing here leaves every
	// remaining row in the database.
	if err := s.verifyArchivedPrefixes(ctx); err != nil {
		return err
	}
	boundary, err := s.store.FindAuditRetentionBoundary(ctx, store.DefaultAuditStream, s.now().UTC().Add(-s.retention))
	if err != nil || boundary == 0 {
		return err
	}
	ref := fmt.Sprintf("audit-prefix-%s-%020d.jsonl", store.DefaultAuditStream, boundary)
	reader, writer := io.Pipe()
	type writeResult struct {
		summary store.AuditArchiveSummary
		err     error
	}
	written := make(chan writeResult, 1)
	go func() {
		summary, writeErr := s.store.WriteAuditPrefix(ctx, store.DefaultAuditStream, boundary, writer)
		if writeErr != nil {
			_ = writer.CloseWithError(writeErr)
		} else {
			writeErr = writer.Close()
		}
		written <- writeResult{summary: summary, err: writeErr}
	}()
	info, putErr := s.archive.Put(ctx, ref, reader)
	if putErr != nil {
		_ = reader.CloseWithError(putErr)
	} else if closeErr := reader.Close(); closeErr != nil {
		putErr = closeErr
	}
	write := <-written
	if putErr != nil {
		return fmt.Errorf("archive audit prefix: %w", putErr)
	}
	if write.err != nil {
		return write.err
	}
	if write.summary.Rows == 0 || len(write.summary.BoundaryHash) != sha256.Size {
		return errors.New("audit archive wrote no usable boundary")
	}
	// info.SHA256 was computed from the bytes as they streamed out and is the
	// value PruneAuditPrefix is about to record durably, so verifying against
	// it proves the archive holds what the checkpoint will claim it holds.
	if err := archive.Verify(ctx, s.archive, ref, info.SHA256); err != nil {
		return fmt.Errorf("verify audit archive: %w", err)
	}
	_, err = s.store.PruneAuditPrefix(ctx, store.AuditRetentionRequest{
		Stream: store.DefaultAuditStream, BoundarySeq: boundary,
		ArchiveDigest: info.SHA256, ArchiveRef: info.Ref, ArchivedAt: s.now().UTC(),
	})
	return err
}

// CleanupAuthStates removes expired one-time OIDC state through the audited
// maintenance store path.
func (s *Service) CleanupAuthStates(ctx context.Context, _ jobs.Job) error {
	_, err := s.store.CleanupExpiredAuthStates(ctx)
	return err
}

// InspectSecurity reports zero enabled global administrators. It does not
// block identity changes: bootstrap-admin is the recovery path.
func (s *Service) InspectSecurity(ctx context.Context, _ jobs.Job) error {
	if ctx == nil {
		return errors.New("security inspection requires a context")
	}
	if s.notifier == nil {
		return nil
	}
	var count int64
	opID := ulid.Make().String()
	_, err := s.store.WithAudit(ctx, backgroundOperation(opID, "maintenance.security.inspect"),
		func(ctx context.Context, tx *store.Tx, rec *store.AuditRecorder) error {
			var err error
			count, err = tx.CountEnabledUnscopedAdmins(ctx)
			if err != nil {
				return err
			}
			rec.Effect(store.AuditEffect{
				ResourceType: "security_posture", ResourceID: opID,
				Action: "INSPECT", Outcome: store.EffectApplied, AfterCount: &count,
			})
			if count == 0 {
				rec.Effect(store.AuditEffect{
					ResourceType: "webhook", ResourceID: opID,
					Action: "NOTIFY_INTENT", Outcome: store.EffectApplied,
				})
			}
			return nil
		})
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return s.notifier.Send(ctx, webhook.Event{
		Name: webhook.EventZeroEnabledAdministrators, OccurredAt: s.now().UTC(),
	})
}

// InspectBackup reports a missing, invalid, or overdue verified SQLite
// backup without changing application readiness.
func (s *Service) InspectBackup(ctx context.Context, _ jobs.Job) error {
	if ctx == nil {
		return errors.New("backup inspection requires a context")
	}
	status, readErr := backupstatus.Read(s.backupPath, s.now().UTC(), s.backupMaxLag)
	stale := readErr != nil || status.Stale
	opID := ulid.Make().String()
	_, err := s.store.WithAudit(ctx, backgroundOperation(opID, "maintenance.backup.inspect"),
		func(_ context.Context, _ *store.Tx, rec *store.AuditRecorder) error {
			rec.Effect(store.AuditEffect{
				ResourceType: "backup_posture", ResourceID: opID,
				Action: "INSPECT", Outcome: store.EffectApplied,
				AfterFlag: &stale, AfterCount: status.LagSeconds,
			})
			if stale && s.notifier != nil {
				rec.Effect(store.AuditEffect{
					ResourceType: "webhook", ResourceID: opID,
					Action: "NOTIFY_INTENT", Outcome: store.EffectApplied,
				})
			}
			return nil
		})
	if err != nil {
		return err
	}
	if !stale || s.notifier == nil {
		return nil
	}
	return s.notifier.Send(ctx, webhook.Event{Name: webhook.EventBackupLag, OccurredAt: s.now().UTC()})
}

type externalAnchorFile struct {
	Version    int       `json:"version"`
	Stream     string    `json:"stream"`
	ChainSeq   int64     `json:"chain_seq"`
	RowHashHex string    `json:"row_hash"`
	CapturedAt time.Time `json:"captured_at"`
}

type externalAnchor struct {
	Ref      string
	Stream   string
	ChainSeq int64
	RowHash  []byte
}

// externalAnchor reads the anchor object stored under ref, reporting whether
// the archive holds it at all.
//
// It performs no digest check against the archive's own sidecar: that would
// compare the object with a claim written beside it, which proves nothing.
// The anchor's authority comes from its content being reproduced by the local
// chain (AuditVerifyOptions.ExpectedAnchor) and, for a position this database
// has already recorded, from agreeing with that append-only row.
func (s *Service) externalAnchor(ctx context.Context, ref string) (externalAnchor, bool, error) {
	if ref == "" {
		return externalAnchor{}, false, errors.New("external audit anchor reference is empty")
	}
	infos, err := s.archive.List(ctx)
	if err != nil {
		return externalAnchor{}, false, fmt.Errorf("list external audit anchors: %w", err)
	}
	var latest *archive.ArchiveInfo
	for _, info := range infos {
		if info.Ref == ref {
			copy := info
			latest = &copy
			break
		}
	}
	if latest == nil {
		return externalAnchor{}, false, nil
	}
	if latest.Size <= 0 || latest.Size > maxAnchorBytes {
		return externalAnchor{}, false, errors.New("external audit anchor has an invalid size")
	}
	rc, err := s.archive.Get(ctx, ref)
	if err != nil {
		return externalAnchor{}, false, err
	}
	decoder := json.NewDecoder(io.LimitReader(rc, maxAnchorBytes+1))
	decoder.DisallowUnknownFields()
	var file externalAnchorFile
	if err := decoder.Decode(&file); err != nil {
		_ = rc.Close()
		return externalAnchor{}, false, fmt.Errorf("decode external audit anchor: %w", err)
	}
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := rc.Close()
	if !errors.Is(trailingErr, io.EOF) {
		return externalAnchor{}, false, errors.New("decode external audit anchor: trailing content")
	}
	if closeErr != nil {
		return externalAnchor{}, false, fmt.Errorf("close external audit anchor: %w", closeErr)
	}
	hash, err := hex.DecodeString(file.RowHashHex)
	if err != nil || file.Version != 1 || file.Stream != store.DefaultAuditStream || file.ChainSeq <= 0 ||
		len(hash) != sha256.Size || file.CapturedAt.IsZero() {
		return externalAnchor{}, false, errors.New("external audit anchor is invalid")
	}
	return externalAnchor{Ref: ref, Stream: file.Stream, ChainSeq: file.ChainSeq, RowHash: hash}, true, nil
}

func backgroundOperation(id, descriptor string) store.AuditOperation {
	return store.AuditOperation{
		OperationID: id, Class: store.ClassBackgroundWriter, ActorType: "control_worker",
		Origin: "in_process", RequestDescriptor: descriptor,
		AuthorizationOutcome: store.AuthorizationNotApplicable,
		Result:               store.ResultSuccess, ResultCode: "OK",
	}
}
