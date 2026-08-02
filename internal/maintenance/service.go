// Package maintenance wires the fixed control-plane housekeeping jobs to the
// durable PostgreSQL scheduler.
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
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/manchtools/power-manage/server/internal/archive"
	"github.com/manchtools/power-manage/server/internal/jobs"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	KindAuditVerify      = "audit.verify"
	KindAuditAnchor      = "audit.anchor"
	KindAuditRetention   = "audit.retention"
	KindAuthStateCleanup = "identity.auth_state_cleanup"

	auditVerifyInterval      = time.Hour
	auditAnchorInterval      = 15 * time.Minute
	auditRetentionInterval   = 24 * time.Hour
	authStateCleanupInterval = time.Hour
	maintenanceMaxAttempts   = int32(100)
	maxAnchorBytes           = 4 << 10
)

var recurring = map[string]time.Duration{
	KindAuditVerify:      auditVerifyInterval,
	KindAuditAnchor:      auditAnchorInterval,
	KindAuditRetention:   auditRetentionInterval,
	KindAuthStateCleanup: authStateCleanupInterval,
}

// Config supplies the fixed maintenance dependencies and operator retention
// policy.
type Config struct {
	Store     *store.Store
	Archive   archive.ArchiveStore
	Retention time.Duration
	Now       func() time.Time
}

// Service implements the production maintenance job handlers.
type Service struct {
	store     *store.Store
	archive   archive.ArchiveStore
	retention time.Duration
	now       func() time.Time
}

// New constructs the maintenance service.
func New(cfg Config) *Service {
	if cfg.Store == nil || cfg.Archive == nil || cfg.Retention <= 0 {
		panic("maintenance: store, archive, and positive retention are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{store: cfg.Store, archive: cfg.Archive, retention: cfg.Retention, now: cfg.Now}
}

// Handlers returns the complete fixed job registry.
func (s *Service) Handlers() map[string]jobs.Handler {
	return map[string]jobs.Handler{
		KindAuditVerify:      s.VerifyAudit,
		KindAuditAnchor:      s.AnchorAudit,
		KindAuditRetention:   s.RetainAudit,
		KindAuthStateCleanup: s.CleanupAuthStates,
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

// VerifyAudit checks the local chain against the newest externally stored
// anchor when one exists.
func (s *Service) VerifyAudit(ctx context.Context, _ jobs.Job) error {
	opts := store.AuditVerifyOptions{CheckStoredAnchors: true}
	external, found, err := s.latestExternalAnchor(ctx)
	if err != nil {
		return err
	}
	if found {
		opts.ExpectedAnchor = &store.AuditAnchor{
			AnchorID: external.Ref, Stream: external.Stream,
			ChainSeq: external.ChainSeq, RowHash: external.RowHash,
		}
	}
	_, err = s.store.VerifyAuditChain(ctx, opts)
	return err
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
	external, found, err := s.latestExternalAnchor(ctx)
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

	ref := fmt.Sprintf("audit-anchor-%s-%020d-%s.json", tip.Stream, tip.Height, ulid.Make().String())
	payload, err := json.Marshal(externalAnchorFile{
		Version: 1, Stream: tip.Stream, ChainSeq: tip.Height,
		RowHashHex: hex.EncodeToString(tip.HeadHash), CapturedAt: s.now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshal audit anchor: %w", err)
	}
	payload = append(payload, '\n')
	if _, err := s.archive.Put(ctx, ref, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("publish audit anchor: %w", err)
	}
	if err := archive.Verify(ctx, s.archive, ref); err != nil {
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
	if err := archive.Verify(ctx, s.archive, ref); err != nil {
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

func (s *Service) latestExternalAnchor(ctx context.Context) (externalAnchor, bool, error) {
	infos, err := s.archive.List(ctx)
	if err != nil {
		return externalAnchor{}, false, fmt.Errorf("list external audit anchors: %w", err)
	}
	anchors := make([]archive.ArchiveInfo, 0, len(infos))
	for _, info := range infos {
		if strings.HasPrefix(info.Ref, "audit-anchor-") && strings.HasSuffix(info.Ref, ".json") {
			anchors = append(anchors, info)
		}
	}
	if len(anchors) == 0 {
		return externalAnchor{}, false, nil
	}
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].Ref < anchors[j].Ref })
	latest := anchors[len(anchors)-1]
	if latest.Size <= 0 || latest.Size > maxAnchorBytes {
		return externalAnchor{}, false, errors.New("external audit anchor has an invalid size")
	}
	ref := latest.Ref
	if err := archive.Verify(ctx, s.archive, ref); err != nil {
		return externalAnchor{}, false, fmt.Errorf("verify external audit anchor: %w", err)
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
