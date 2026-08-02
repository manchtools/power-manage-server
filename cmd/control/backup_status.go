package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/manchtools/power-manage/server/internal/backupstatus"
)

func runBackupStatus(output, diagnostics io.Writer, cfg *Config, now func() time.Time) int {
	if output == nil || diagnostics == nil || cfg == nil || now == nil {
		return 1
	}
	status, readErr := backupstatus.Read(cfg.BackupPath, now().UTC(), cfg.BackupMaxLag)
	if readErr != nil {
		if _, err := fmt.Fprintln(diagnostics, "backup-status:", readErr); err != nil {
			return 1
		}
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(status); err != nil {
		return 1
	}
	if readErr != nil || status.Stale {
		return 1
	}
	return 0
}
