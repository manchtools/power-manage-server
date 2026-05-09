// Package payloads holds the shared JSON-shape structs that travel in
// the events table's data column. Each struct is the single source of
// truth for one event type's wire format: the handler emit site
// constructs an instance, AppendEvent json.Marshals it into JSONB, and
// the projector decoder json.Unmarshals it back out. Sharing one
// struct between emit and decode catches schema drift (renamed field,
// typo'd key, dropped field) at compile time instead of at projection
// replay.
//
// Field-tag rules:
//
//   - Preserve the json tag exactly as it appears in the legacy
//     handler-side map[string]any literal. Any change to the wire key
//     is a migration, not a refactor — old events in the events table
//     must keep decoding cleanly.
//   - omitempty matches what the deleted PL/pgSQL projector expected.
//     A field that the projector treats as "missing key falls back to
//     existing column value" must use omitempty so the struct's zero
//     value round-trips as an absent key, not as a JSON null that
//     overwrites the column.
//   - Pointer types preserve the absent-vs-explicit-zero distinction.
//     Use them when the projector's COALESCE semantics depend on it
//     (DeviceSeen.AgentVersion, UserSshSettingsUpdated.SshAccessEnabled,
//     etc.).
//   - json.RawMessage is used for nested JSONB blobs (action params,
//     device labels, schedule) so wire bytes pass through verbatim
//     without a marshal/unmarshal round trip.
//
// Roundtrip tests in payloads_test.go assert that every payload struct
// survives a json.Marshal -> json.Unmarshal cycle byte-identical, so a
// future field-tag typo or accidental encoding-changing edit fails CI
// before reaching production.
package payloads
