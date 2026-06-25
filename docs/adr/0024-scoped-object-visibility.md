# 0024 — Scoped object visibility (assignment-keyed RBAC for actions/sets/definitions/policies)

- Status: accepted
- Date: 2026-06-25
- Related: server#7 (Scoped Access); spec `docs/content/06-specs/14-scoped-object-visibility.md`;
  ADR 0006 (handler-level, uniform scope enforcement); spec 13 / #325 (search index).

## Context

Scope enforcement (#7 / ADR 0006) confines a scoped admin to their device/user
groups for ~61 permissions — devices, users, groups, dispatch, terminal, lists.
But every action / action-set / definition / compliance-policy permission was
`TargetUnspecified` (not scopable), so a device-group-scoped operator could
`Search`, `Get`, and **mutate** the entire org catalog: every action's
`ShellParams` script and `FileParams` contents, every definition, every
compliance policy (the org's complete security posture). That is information
disclosure — and unauthorized mutation — past the operator's scope: a V1 security
gap, not a V2 nicety.

The shared objects have no per-user owner; they are reached by **assignment** to
device/user groups (or individual devices/users). So the natural confinement is:
*a scoped admin sees and manages only objects assigned within their scope.*

## Decision

### Confinement model

- **Caller scope = the union of the device-group and user-group ids the caller's
  JWT scoped grants confine them to.** Object permissions are not independently
  scopable; the confinement reuses the device-/user-group scope the caller
  already holds (`auth.ObjectScopeListFilter`, JWT-only — no DB round-trip). A
  caller with no scoped grant is a global admin (unrestricted, as today).

- **Read uses EFFECTIVE scope, write uses DIRECT scope.**
  - *Effective* = the object's own assignment groups **plus** its containers'
    (action → sets/definitions; set → definitions). An action that runs on your
    fleet via an assigned definition is *visible*.
  - *Direct* = the object's own assignment groups only. Editing a set never
    implies editing its member actions; a transitively-visible object is not
    writable.

- **Out-of-scope `Get` → `NotFound`** (never `PermissionDenied` — no existence
  leak), with the true reason logged at WARN so denials are observable.
  **Out-of-scope mutation → `PermissionDenied`.**

### Why the index carries DIRECT group targets, not effective groups

The search index field `scope_group_ids` (multi-value TAG on the four object
indexes) holds only the object's **direct device-/user-group target** assignment
ids — *not* effective groups, and *not* device/user targets resolved to groups.
Rationale:

- **Full freshness with no new cascade.** A direct group-target edge changes only
  on the object's *own* `AssignmentCreated/Deleted`, which already reindexes the
  object. There is no projection table, no container cascade, and no
  membership-change cascade to keep correct — the field can never go stale-high
  (the failure mode that would *leak*).
- **Transitivity and device/user→group resolution are resolved live in the
  handler** (`Get` effective walk; both `Get` and mutation resolve device/user
  targets through membership). These are single-object lookups, always fresh.

The cost is that a scope-restricted **Search** under-shows objects that are only
*transitively* in scope, or assigned to an individual device/user rather than a
group — they don't appear in the list, but remain readable via `Get`. This is
**fail-closed** (a scoped admin sees *less*, never more) and the dominant case —
objects assigned to a *group* — is exact. Full effective-search is a deferred
refinement, not a leak.

### No proto change

Scope is derived server-side from the caller's JWT grants; no request field is
added, so a client cannot widen its own scope. `scope_group_ids` is a
**server-only** index field (`search.ServerScopeFields`) — populated and filtered
by the server, never exposed as a client filter (the `scopeFilterFields` parity
guard skips it).

### Self-discovering parity

`TestObjectScope_EnforcementMatchesIndexFiltering` AST-scans the package for
`enforceObjectReadScope` / `enforceObjectWriteScope` calls and requires the set of
handler-enforced object types to equal the set of search scopes declaring
`scope_group_ids` (both ways, with a matches-zero guard). Index-filtering without
handler enforcement (a `Get` leak) or vice-versa (a `Search` leak) fails the
build.

## Consequences

- A scoped admin's object lists/reads/mutations are confined to their scope;
  unassigned objects are invisible to them (managed only by global admins).
- Global admins are entirely unaffected (the restricted-gate short-circuits
  before any extra DB work).
- **Known boundary (documented, fail-closed):** transitive-only and
  individual-device/user-assigned objects under-show in `Search` for scoped
  callers; they remain reachable via `Get`.
- **Out of scope of this ADR — a related, broader leak:** the `Search` RPC also
  applies *no* device/user scope today, so the device/user **list pages** (which
  use `Search`, not the scoped `ListDevices`/`ListUsers` RPCs) leak the whole org
  to a scoped admin. Closing it needs the same `scope_group_ids` mechanism on the
  device/user indexes plus a membership-change reindex cascade — and, for
  *dynamic* groups (whose re-evaluation emits a **bulk** `*MembersRebuilt` event,
  not per-member), an explicit eventual-consistency tradeoff on an access-control
  filter. That design decision is deferred to a follow-up rather than shipped
  implicitly here.
