# 0033 — Audit-log retention window + crypto-shred erasure contract

- Status: accepted
- Date: 2026-07-18
- Related: spec 19 (docs repo, `06-specs/19-audit-retention-and-erasure.md`);
  ADR 0029 (all Postgres state is event-sourced or classified — **amended** by
  this ADR: `user_encryption_keys` is the sole durable-non-recoverable,
  non-event-sourced exception); ADR 0030 (single AAD at-rest format — the DEK
  wraps under its `enc:v1:` envelope); ADR 0001 (AES key rotation — the DEK
  envelope enables cheap KEK rotation for PII).

## Context

Spec 19 introduced two things the event-sourcing contract (ADR 0029) had no
place for:

1. **A right-to-erasure that survives an append-only log.** The events table is
   immutable by design (ADR 0026/0029: it is both the system of record and the
   audit log, and replay must reproduce state 1:1). PII written into an event
   payload can therefore never be deleted or overwritten. GDPR erasure demands
   the opposite. Hard-deleting events, or holding PII out of the log in a
   separate deletable store, would each break the replay guarantee.
2. **A bounded audit-retention window with off-box archival.** An unbounded
   event log grows without limit and keeps audit records past any lawful
   retention period; pruning old events must not silently discard them, and the
   pruned data must remain independently auditable.

Spec 19's References section names an ADR for this contract but the number it
reserved (0030) was taken by the unrelated single-AAD-format ADR (spec 20).
This ADR is the record spec 19 always intended; it is written now to close that
gap and to record the ADR-0029 amendment explicitly rather than only in prose.

## Decision

**Crypto-shred is the erasure mechanism.** Every user is minted one random
32-byte data-encryption key (DEK) at creation. PII-tagged event-payload fields
(`pii:"true"`) are sealed under the *subject* user's DEK before append (format
tag `pii:v1:`, distinct from the `enc:v1:` at-rest secret format); projectors
unseal at projection-build time. Deleting the user destroys the one
`user_encryption_keys` row, which makes every copy of that person's PII — live
log, cold archives, and any future rebuild — permanently unreadable at once,
without ever mutating the append-only log.

- **Fail-closed sealing (spec 19 AC 6).** A sealing error aborts the append. The
  log is immutable, so plaintext PII written once is unerasable forever; refusing
  the write is always cheaper than an un-shreddable leak.
- **Atomic shred (spec 19 AC 7/14).** The `UserDeleted` append and the DEK-row
  delete happen in ONE transaction (`AppendUserDeletionWithShred`) — all or
  nothing. A failed shred rolls the deletion back; there is no half-erased state.
- **Redaction on missing DEK.** A projector that finds a sealed PII value with no
  DEK projects the redaction sentinel — a shredded user's projection is
  indistinguishable from one that was never populated.

**`user_encryption_keys` is the sole durable-non-recoverable exception (amends
ADR 0029).** It is classified as by-design non-event-sourced operational state
with a unique justification: it *cannot* be event-sourced (that would make the
key un-destroyable, defeating erasure) and *cannot* be regenerated (random key
material). It is therefore **jointly authoritative with `events`**: the recovery
contract is that both must be backed up and restored together. A rebuild from
the event log alone completes, but reproduces every user's PII as the redaction
sentinel — indistinguishable from mass erasure. The event log is no longer a
self-sufficient source of truth for PII.

**Retention is a bounded window with sealed off-box archival.** A scheduled,
advisory-lock-single-flighted prune worker archives events older than the
configured window to an integrity-sealed `ArchiveStore` before deleting them
from `events`; tampering with any archived byte is detectable and an archive can
be replayed out-of-band for audit without the live system. Retention that is
enabled but misconfigured is a fail-closed boot refusal (a restart would
otherwise silently keep or drop the wrong events).

**Enforcement / runtime alarm.** `control doctor` is the safety net, not a
projector: it checks the per-user key invariants crypto-shred depends on (every
live user's DEK unwraps; no erased user retains one), erased-user teardown, and
the retention posture — flagging drift before a prune makes it unrecoverable.

## Alternatives considered

- **Hard-delete events for an erased user.** Rejected — it breaks the replay
  guarantee (ADR 0029) and destroys the audit trail of everything that user did,
  not just their PII. Crypto-shred erases the *identity* while leaving the
  pseudonymised audit history (actor ULID with no way back to the person) intact.
- **Hold PII in a separate deletable table, keyed from events.** Rejected — two
  systems of record for one fact, and the join key (ULID) plus any denormalised
  copy in the log would still leak. The DEK envelope keeps PII *in* the log but
  cryptographically gated by one deletable row.
- **Event-source the DEK.** Rejected — an event-sourced key is reproducible from
  the log, so it could never be truly destroyed. The one non-event-sourced row is
  the point.

## Consequences

- `user_encryption_keys` is the single most backup-critical table in the system;
  losing it is mass erasure. This is stated in the operator recovery docs and
  guarded at runtime by doctor's dual key-invariant check.
- Erasure is O(1) (destroy one row) regardless of how much PII the user
  accumulated across the log and archives.
- Pseudonymisation, not anonymisation: an erased user's actor ULID remains in the
  audit history with the person-mapping severed. Sufficiency depends on the legal
  basis — the accepted residual-risk posture, recorded in spec 19's Security
  section.
- Retention pruning is irreversible for the live system once the sealed archive
  is the only copy; the archive seal is what keeps it auditable.
