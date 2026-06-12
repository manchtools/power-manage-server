# 0004 — Action/event representation is proto-native (single source per shape)

- Status: accepted
- Date: 2026-06-13
- Related: server#401; sdk#82; WS1b of the SECURITY_HARDENING_WORKPLAN;
  ADR 0002 (fitness functions); ADR 0003 (full-envelope action signing).

## Context

ADR 0003 fixed the action *signing* bug by signing the full executed envelope as
deterministic binary protobuf. A focused architecture sweep found that bug sat
at the centre of a *cluster* of representation smells — the same data modelled
twice, in incompatible ways, each pairing a hand-maintained projection with a
hand-maintained parse that had to be kept in lockstep by eye:

1. **Six `ActionType → params message` switch tables** (`PopulateAction`,
   `PopulateEnvelope`, `PopulateManagedAction`, the three `extract*ParamsMsg`
   helpers) plus the `validateCreate/Update` validators and
   `actionParamsMatchType` — all re-encoding a mapping the proto `params` oneof
   already *is*. A new `ACTION_TYPE_*` had to be added in six places or it
   silently dispatched with empty params.
2. **`ExecutionCreated` / `ExecutionScheduled` emitted as `map[string]any`** at
   the two busiest dispatch emitters, while every other emitter + the projector
   used the typed `payloads.Execution*` — reintroducing the exact twin-drift the
   `payloads` package exists to prevent.
3. **The derived-execution dedup id hashed over a `:`-joined, time-formatted
   string** — unframed (a `:` in a device/action id collided field boundaries)
   and mixing two pre-image domains (RFC3339Nano timestamp vs `dur:status`
   fallback) with no variant tag. Same pre-image-ambiguity class as the signing
   bug ADR 0003 closed.
4. **`ActionSchedule` hand-projected to a map and hand-parsed from an anonymous
   struct** — the field set declared three times; `ScheduleToMap` dropped zero
   values, so an explicitly-set zero was indistinguishable from unset.
5. **`pm.CommandOutput` (de)serialised with stdlib `encoding/json`** at four
   sites — the wrong codec, working only by snake-case-tag luck, silently
   breaking on any future oneof/enum/int64/well-known-type field.

## Decision

Action and event data is **proto-native**: one representation per shape, with
the proto as the single source of truth. JSONB remains a *storage* format (its
queryability is worth keeping), but proto-derived columns use **protojson**, not
stdlib `encoding/json`.

1. **One proto-reflection params registry.** A single
   `map[pm.ActionType]protoreflect.Name` (`actionparams.paramsFieldByActionType`)
   maps each params-carrying type to its `params`-oneof field. `populateParamsOneof`
   (`protoreflect` set), `ExtractParamsMsg` (`WhichOneof` get), and
   `ParamsMatchType` replace all six switch tables; the validators keep only the
   two genuinely type-specific extras (shell script-choice, agent-update
   arch/HTTPS). `TestEveryActionTypeHandledInEveryParamsSwitch` pins the registry
   complete and consistent against every params-bearing message's live descriptor.
2. **Typed event payloads.** Dispatch emits `payloads.ExecutionCreated` /
   `ExecutionScheduled` structs (params as `json.RawMessage`), never an ad-hoc
   map; `TestExecutionCreatedEmittedTyped` decodes the emitted event strictly
   (unknown fields disallowed) into the typed payload.
3. **Framed, domain-separated dedup id.** `stableExecutionID` hashes a
   length-prefixed (`uint32`-framed) pre-image with a domain separator and a
   per-variant tag, keying the timestamp variant off the proto `Timestamp`'s
   `(seconds, nanos)` rather than a formatted string. Mirrors the signing
   digest's framing.
4. **protojson schedule round-trip.** `ScheduleToRaw` / `ScheduleFromJSON` use
   the shared protojson options; the field set is declared once (the proto). An
   all-default schedule still serialises to nil so the emitter omits the key and
   the projector applies its `{"interval_hours": 8}` drift default — but any
   non-empty schedule now carries its explicit zero values on the wire.
5. **protojson for `CommandOutput`.** One `decodeCommandOutput` helper (protojson)
   replaces four hand-rolled decode sites. protojson accepts both the camelCase
   it emits and the legacy snake_case, so existing event/store bytes still decode.

## Consequences

- A new `ACTION_TYPE_*` needs exactly one registry entry (or a param-less
  classification); the completeness fitness function fails until it is wired.
- `TestNoStdlibJSONOfProtoMessage` (ADR 0002 family) makes the stdlib-json-of-proto
  smell build-failing, so it cannot return. The agent's local store carries the
  same guard in its archtest package.
- **Migration note (pre-1.0, no stable release):** the dedup-id pre-image change
  means an agent-scheduled result that was *already processed* under the old id
  scheme and is *retried across the deploy* computes a new id and creates one
  duplicate execution row — a one-time, narrow transient. Acceptable while the
  re-tag-in-place freedom holds (see the pre-1.0 gate in the workplan). The
  schedule and CommandOutput readers accept the legacy wire shapes, so historical
  event-store data rehydrates unchanged.
- This is part of the pre-1.0 representation rework that MUST merge before a
  stable `vYYYY.MM.0` tag (alongside WS1), after which field/representation
  changes acquire a lazily-updating installed base.
