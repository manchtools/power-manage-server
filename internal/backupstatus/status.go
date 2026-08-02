// Package backupstatus reads the small marker written after a verified backup.
package backupstatus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// StatusFilename is atomically replaced only after pg_restore accepts a dump.
	StatusFilename = "postgres-backup-status.json"
	maxStatusBytes = 4 << 10
	maxClockSkew   = 5 * time.Minute
)

type marker struct {
	Version     int       `json:"version"`
	CompletedAt time.Time `json:"completed_at"`
	Artifact    string    `json:"artifact"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
}

// Status is the operator-facing backup posture. A missing marker is stale,
// not an application-readiness failure.
type Status struct {
	Version              int        `json:"version"`
	LastSuccessfulBackup *time.Time `json:"last_successful_backup"`
	LagSeconds           *int64     `json:"lag_seconds"`
	MaxLagSeconds        int64      `json:"max_lag_seconds"`
	Stale                bool       `json:"stale"`
	Artifact             string     `json:"artifact,omitempty"`
	SizeBytes            int64      `json:"size_bytes,omitempty"`
	SHA256               string     `json:"sha256,omitempty"`
}

// Read validates the latest verified-backup marker and calculates its age.
func Read(directory string, now time.Time, maxLag time.Duration) (Status, error) {
	base := Status{Version: 1, MaxLagSeconds: int64(maxLag / time.Second), Stale: true}
	if directory == "" || now.IsZero() || maxLag <= 0 {
		return base, errors.New("backup status requires a directory, clock, and positive maximum lag")
	}
	path := filepath.Join(directory, StatusFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return base, nil
	}
	if err != nil {
		return base, fmt.Errorf("inspect backup status: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxStatusBytes {
		return base, errors.New("backup status must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return base, fmt.Errorf("open backup status: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxStatusBytes+1))
	decoder.DisallowUnknownFields()
	var stored marker
	if err := decoder.Decode(&stored); err != nil {
		return base, errors.New("decode backup status")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return base, errors.New("backup status has trailing content")
	}
	digest, digestErr := hex.DecodeString(stored.SHA256)
	if stored.Version != 1 || stored.CompletedAt.IsZero() || stored.CompletedAt.After(now.Add(maxClockSkew)) ||
		stored.Artifact == "" || filepath.Base(stored.Artifact) != stored.Artifact || stored.SizeBytes <= 0 ||
		digestErr != nil || len(digest) != 32 {
		return base, errors.New("backup status is invalid")
	}
	artifactInfo, err := os.Lstat(filepath.Join(directory, stored.Artifact))
	if err != nil || !artifactInfo.Mode().IsRegular() || artifactInfo.Size() != stored.SizeBytes {
		return base, errors.New("backup artifact does not match its status")
	}

	completed := stored.CompletedAt.UTC()
	lag := now.UTC().Sub(completed)
	if lag < 0 {
		lag = 0
	}
	lagSeconds := int64(lag / time.Second)
	return Status{
		Version: 1, LastSuccessfulBackup: &completed, LagSeconds: &lagSeconds,
		MaxLagSeconds: int64(maxLag / time.Second), Stale: lag > maxLag,
		Artifact: stored.Artifact, SizeBytes: stored.SizeBytes, SHA256: stored.SHA256,
	}, nil
}
