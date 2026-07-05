package payloads

// EventLogPruned is the wire shape for the EventLogPruned event the
// retention prune worker appends (spec 19). It records that all events
// with sequence_num <= UpToSeq were sealed into an integrity-checked
// cold archive (ArchiveRef, ArchiveSHA256) and then deleted from the
// live log. Carries NO PII and NO key material — only the checkpoint
// and the archive pointer/seal, so the prune chain is auditable from
// the live log alone and this event is itself exempt from pruning.
type EventLogPruned struct {
	UpToSeq       int64  `json:"up_to_seq"`
	ArchiveRef    string `json:"archive_ref"`
	ArchiveSHA256 string `json:"archive_sha256"`
}
