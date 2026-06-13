# 0006 — Scope enforcement is handler-level and uniform; scopable == enforced

- Status: accepted
- Date: 2026-06-13
- Related: server#7 (scoped device-group RBAC pilot), server#369 (atomic
  last-admin), server#391; WS3 of the SECURITY_HARDENING_WORKPLAN (findings
  #3/#19, and the grant-ceiling reversal that voids #1/#2/#12); ADR 0000
  (TerminalAdmin threat model). Builds on PR #405 (role-mgmt is the sole grant
  gate) and PR #406 (the single-resource gate layer, part 1).

## Context

server#7 introduced **scoped role grants**: a role assignment may carry a scope
(`device_group:<id>` or `user_group:<id>`), so an actor can hold a permission
confined to the devices/users in that group. The grant data model, the JWT
`sgrants` claim, and the scope-authority checks (who may *attach* a scope) all
shipped. But **only `StartTerminal` actually enforced the scope at call time.**
Every other TargetDevice/TargetUser handler read the flat permission set, saw the
base permission present (the scope lives on the grant, not the permission string),
and waved the caller through to the whole fleet. Scope was therefore **advisory**
almost everywhere — a scope-limited admin had org-wide reach in practice.

Two adjacent decisions frame this one:

- **No grant ceiling (PR #405).** Holding a role-management permission
  (`AssignRoleToUser`, `CreateUser`, …) authorizes assigning *any* role,
  including Admin, with no secondary "do you personally hold every permission you
  grant" check. The role-management permission is the sole gate. Scope
  enforcement is a *separate axis* — it confines *which devices/users* an actor
  may act on, not *which permissions* they may confer — and is still wanted.
- **Scopable must equal enforced (no advisory scope).** A permission marked
  scopable (`TargetKind != TargetUnspecified`) that isn't actually enforced is a
  lie to the operator who scoped it. The fix is to either enforce it or de-scope
  it — never to keep an allowlist of "scopable but not really" permissions.

## Decision

Enforce device-group / user-group scope **uniformly at the handler layer**, on
**every** scopable permission, and pin "scopable == enforced" with a
self-discovering test.

1. **One tiered model, five mechanisms.** The flat permission set is the
   AUTHORITY (it decides *whether* the actor holds the base permission); the
   scoped grants only CONFINE (they decide *which* targets). A base holder with
   no scoping grant is unrestricted (production always carries an unscoped grant
   for an unscoped role; the test fixtures carry none — both read as
   unrestricted). A base holder with a same-kind scoped grant is confined to it.
   A base holder with only a *wrong-kind* grant fails **closed**. The mechanisms,
   all in `internal/auth/scope.go` + the handlers:
   - **Single-resource gates** — `EnforceDeviceScopeOnBaseTier` /
     `EnforceUserScopeOrSelf` for handlers acting on one device/user id (Get,
     Delete, Dispatch, inventory, logs, compliance, the user gates, …). The
     `:assigned` / `:self` tier passes through to the existing owner SQL filter.
   - **Group-id direct-match gates** — `EnforceDeviceGroupScope` /
     `EnforceUserGroupScope` for group-management handlers (rename, delete,
     description, windows, get): the GROUP id itself must be one of the caller's
     scope ids — a direct match, not a membership lookup.
   - **List-row filters** — `DeviceScopeListFilter` / `UserScopeListFilter`
     return `(groupIDs, restricted)`; list queries gain a `(scope_restricted
     bool, scope_group_ids text[])` parameter pair and confine rows by membership
     (devices/users/executions) or by direct id-match (group lists). The matching
     COUNT query takes the same restriction so pagination totals stay honest and
     don't leak the out-of-scope count. `ListActiveTerminalSessions` filters its
     merged in-memory list the same way.
   - **Dispatch fan-out** — `enforceDeviceScopeAll` checks *every* target device
     and fails the whole request closed if any is out of scope (dispatch is
     mutating; partial/silent execution is worse than a clear denial).
   - **Reconciler cohort** — `TerminalAdminLimited` / `TerminalAdminFull` are
     enforced by the per-scope sudo-cohort computation in `system_actions.go`
     (`switch g.Permission`), not a request-time gate (ADR 0000).

2. **De-scope what cannot be enforced.** Group CREATION
   (`CreateStaticDeviceGroup`, `CreateStaticUserGroup`) is now **org-tier**
   (`TargetUnspecified`): a brand-new group has no id and no members, so there is
   nothing to confine a scope against at create time. Marking it scopable would
   be advisory-only. Scope is enforced on the downstream management + membership
   operations instead. (Dynamic-group create was already org-tier per T-S2.)

3. **Membership check on member-add, to stop a scope escape.**
   `AddDeviceToGroup` / `AddUserToGroup` check BOTH the target group (direct
   id-match) AND that every device/user being added is **already within the
   caller's scope** (membership). Without the member check a scope-limited admin
   could pull any fleet device/user into a group they control and so expand their
   own scope. Removal needs only the group check — it cannot expand scope.

4. **Self-discovering parity (the load-bearing guard, #19).**
   `TestScopablePermissions_AllEnforced` AST-scans `internal/api` for permission
   string-literals passed to the recognized scope functions (and the reconciler's
   `switch g.Permission`) and asserts the enforced set EQUALS the scopable set
   from `auth.AllPermissions()`, in both directions. A new TargetDevice/TargetUser
   permission added without enforcement fails the test; so does enforcing a
   permission the registry no longer marks scopable (a stale TargetKind). Only the
   small set of enforcement *mechanisms* is enumerated — forgetting to register a
   new mechanism fails the test CLOSED (its permissions read as unenforced).

## Consequences

- A scope-limited admin is now genuinely confined to their device/user groups on
  every read, list, mutation, dispatch, terminal op, and the TTY sudo cohort —
  not just `StartTerminal`. "Scopable" is now an honest, testable claim.
- Shared queries used by the scope resolver itself (`ListGroupsForDevice`,
  `ListUserGroupsForUser`) stay UNFILTERED in SQL — filtering them would corrupt
  scope resolution — and their handlers filter in Go instead.
- The scope checks fail closed on an unauthenticated context, so handler tests
  that drive a handler with a bare `context.Background()` now see
  `Unauthenticated` / empty results; such tests are given an auth context. This
  is the intended fail-closed behavior, not a regression.
- List queries grew a `(scope_restricted, scope_group_ids)` parameter pair; the
  boolean carries the restrict-or-not decision so SQL behavior never depends on
  pgx's nil-vs-empty array encoding. Regenerated via `make sqlc-generate`.
- Scope enforcement and the grant-ceiling removal are orthogonal and both hold:
  *what* you may confer is gated solely by the role-management permission; *which
  targets* you may act on is gated by scope.
