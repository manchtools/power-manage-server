# ADR 0000 — TerminalAdmin threat model & mitigation matrix

| Status | Date | Gates |
| --- | --- | --- |
| Proposed | 2026-06-08 | [manchtools/power-manage-server#70](https://github.com/manchtools/power-manage-server/issues/70) (TerminalAdmin), [#7](https://github.com/manchtools/power-manage-server/issues/7) (scoped RBAC) |

## TL;DR

The plumbing for TerminalAdmin already exists. Four pieces are
already in production:

1. **Per-operator nologin Linux account** —
   `pm-tty-<linux_username>`, fanned out automatically to every device
   the operator holds `StartTerminal` on
   ([`server/internal/api/system_actions.go:392`](../../../server/internal/api/system_actions.go#L392)).
   Hidden, no home, deterministic UID. Agent flips the shell to
   `/bin/bash` for the duration of a session and back to `nologin`
   afterward ([`agent/internal/handler/terminal.go:343`](../../../agent/internal/handler/terminal.go#L343)).
2. **`pm-tty-*` accounts are truly passwordless** — as of
   [sdk #77](https://github.com/manchtools/power-manage-sdk/pull/77),
   [agent #94](https://github.com/manchtools/power-manage-agent/pull/94),
   and [server #328](https://github.com/manchtools/power-manage-server/pull/328)
   (umbrella #327), the agent skips chpasswd + chage when
   `UserParams.no_password=true`, and `syncTtyUserAction` sets that
   flag for every pm-tty-\* account. The shadow password field sits at
   `*` — "no password, **not** locked" (as of
   [sdk #259](https://github.com/manchtools/power-manage-sdk/pull/259):
   only a leading `!` means locked, and `usermod -U`/`-p '*'` is
   passwordless-aware; earlier code left `!` here and treated it as
   locked, which stranded enabled accounts as "disabled"). A leading
   `!` is reserved for the **disabled/offboarded** state — see the
   "Account lock and session activation are separate domains" invariant
   under Decision. No LPS row is emitted. The operator cannot retrieve a
   password they could re-use for sudo — there is none.
3. **AdminPolicy executor** ([`agent/internal/executor/sudo.go`](../../../agent/internal/executor/sudo.go)) —
   creates a Linux group + sudoers drop-in + manages member usernames,
   with two presets (`FULL`, `LIMITED`) already templated.
4. **Terminal session input-audit pipeline** — keystrokes are
   batched, dispatched as `TerminalAuditChunk` Asynq tasks, and
   appended to the `terminal_sessions` table by
   [`InboxWorker.handleTerminalAuditChunk`](../../../server/internal/control/inbox_worker.go#L929).
   Every chunk carries the **human** `UserID`, so the
   `pm-tty-* → human-user` identity mapping is already preserved.

**What #70 actually adds** is the role-driven layer that connects
them: when a user holds the new `TerminalAdminLimited` (or `Full`)
permission, their `pm-tty-<username>` account is added to the LIMITED
(or FULL) system-managed AdminPolicy action's `users` list. Same
fan-out shape as the existing tty-user action.

> **#7 model update (2026-06-10, "Model Y"):** the sudo cohort is
> driven by `TerminalAdmin{Limited,Full}` **alone** — `StartTerminal`
> is **not** required. `StartTerminal` drives the separate `pm-tty`
> account; the LIMITED/FULL sudo policy is harmless/inert on a device
> where the account doesn't exist (group rule, empty membership; the
> agent SKIPs gracefully). Each permission is scoped independently —
> the LIMITED/FULL action reaches a device when the holder's
> `TerminalAdmin*` scope covers it; the account reaches a device when
> the holder's `StartTerminal` scope covers it. This replaces the
> earlier `StartTerminal ∩ TerminalAdmin` cohort. (PR1 decoupled the
> global cohort; PR2 adds the per-scope actions + scope-aware
> delivery.)

The catch is one small but load-bearing detail: **the existing
LIMITED/FULL templates require a password**, and `pm-tty-*` accounts
genuinely have no password (point 2 above). So the templates must be
**NOPASSWD** before they're usable through this path. Adding
NOPASSWD is not a friction-removal — it's the only configuration
that works at all. It does raise the bar for what the LIMITED
allowlist must reject: the operator can `sudo cmd` with zero
friction, so any cmd that escapes to a shell is an immediate root.

This ADR pins what the LIMITED template must reject under NOPASSWD,
what revocation has to do, and what acceptance tests #70's PR has to
turn green. **Five threats**, each with a falsifiable test. Most
mitigations are small additions to existing files.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4 — Scope (#7, paired)                                    │
│   TerminalAdminLimited:scope on device_group_X                  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3 — RBAC permission  (NEW — small)                        │
│   TerminalAdminLimited / TerminalAdminFull                      │
│   Held by user U → resolution layer adds "pm-tty-U" to the      │
│   users list of the LIMITED/FULL system action on each device   │
│   in U's TerminalAdmin* scope (StartTerminal NOT required —      │
│   it drives the separate pm-tty account; #7 Model Y).           │
└─────────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2 — Two system-managed AdminPolicy actions (NEW — small)  │
│   • system:terminal-admin-limited  (access_level=LIMITED)       │
│   • system:terminal-admin-full     (access_level=FULL)          │
│   New SystemActionManager method, mirrors syncTtyUserAction.    │
│   Delivered to every device. users[] = resolved pm-tty-* list.  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1 — AdminPolicy executor  (EXISTS — small polish)         │
│   agent/internal/executor/sudo.go                               │
│   • creates pm-sudo-<actionID> Linux group                      │
│   • writes /etc/sudoers.d/pm-sudo-<actionID>                    │
│   • syncs member list (gpasswd add/remove)                      │
│   • LIMITED / FULL templates already present                    │
│   Deltas in #70: NOPASSWD, deny rules for editors/shells/cron,  │
│   tighter Defaults block.                                       │
└─────────────────────────────────────────────────────────────────┘
                              ▲
┌─────────────────────────────────────────────────────────────────┐
│ Layer 0 — pm-tty-<user> account + terminal session audit        │
│   (EXISTS — passwordless as of #327, no change for #70)         │
│   • UserParams system action creates the account everywhere     │
│     U holds StartTerminal. NoPassword=true → shadow stays at    │
│     '!', no LPS row emitted (sdk #77, agent #94, server #328).  │
│   • Session input is batched, dispatched as TerminalAuditChunk, │
│     and stored in terminal_sessions with the human UserID.      │
└─────────────────────────────────────────────────────────────────┘
```

## Trust model

### Assets

| # | Asset | Why it matters |
| --- | --- | --- |
| A1 | Root on the managed device | Direct compromise; lateral movement. |
| A2 | The agent's signing key / cert | Forge actions, impersonate the device. |
| A3 | The session audit pipeline | Erasing or pre-empting evidence of A1/A2 abuse. |
| A4 | Other operators' sessions on the same device | Stealing credentials, screenshotting their shells. |
| A5 | `power-manage-agent` itself (process, unit, config) | Disabling enforcement; tamper-on-detection. |

### Adversary

Authenticated operator who holds `StartTerminal` + `TerminalAdminLimited`,
has opened a session against device D, and is now running an
interactive `/bin/bash` as `pm-tty-<their-username>`. Goals:

- **G1.** Escalate to a root shell or arbitrary-command execution
  through the LIMITED allowlist.
- **G2.** Read / modify other operators' sessions on the same device.
- **G3.** Disable or modify the enforcement (agent, sudoers,
  terminal-audit pipeline).
- **G4.** Persist beyond revocation — leave behind a backdoor that
  survives `gpasswd -d` removing them from the limited group.

We do **not** assume the operator is a kernel-exploit author
(out of scope; mitigated by patch policy, which the LIMITED allowlist
explicitly enables). We **do** assume they read source code, study
the sudoers fragment we install, and try every documented escape.

## Security contract (Limited)

A `TerminalAdminLimited` grant must satisfy each of the following.
Each is **falsifiable**: a single counterexample fails the grant.

> **L1.** The `pm-tty-<user>` account cannot execute a binary
> outside the LIMITED template's resolved-absolute-path allowlist
> as root.
>
> **L2.** No binary in the allowlist provides a documented escape
> to an arbitrary command or interactive shell.
>
> **L3.** Revoking the permission stops all *future* sudo calls
> for that pm-tty user, on every in-scope device, within the
> resolution-fanout interval. **In-flight elevated commands are
> allowed to complete.** (See "Consequences — in-flight commands"
> below for why this trade-off is acceptable given the existing
> session-kill mechanisms.)
>
> **L4.** The operator cannot disable, edit, or starve the
> sudoers fragment, the `pm-sudo-<actionID>` group's contents, or
> the `power-manage-agent` process — including via systemd,
> packaging tools, filesystem mounts, kernel modules, or
> auditd-disable paths reachable from the allowlist.
>
> **L5.** The grant is **deny-by-default**: anything not in the
> allowlist is rejected. The allowlist matches **resolved absolute
> paths**, never command basenames, never wildcards on `*`.

## Threat → mitigation matrix

Conventions:

- **Threat:** adversary capability we're closing off.
- **Test:** falsifiable check.
- **Status:** `MITIGATED` (current code already enforces) /
  `PARTIAL` / `GAP` (#70 must add).

### T1 — NOPASSWD is mandatory and changes the threat surface

**Threat.** The existing `generateLimitedSudoConfig`
([`agent/internal/executor/sudo.go:156`](../../../agent/internal/executor/sudo.go#L156))
emits rules of the form `%group ALL=(ALL) /usr/bin/apt, …` — sudo
prompts for a password. As of #327 the `pm-tty-*` account is created
with `NoPassword=true`, so the shadow entry stays at `!` and no
password exists. With the existing template under TerminalAdmin,
**the operator cannot use sudo at all**: no password = no
elevation, even for allowed commands.

The fix is `NOPASSWD:`. That fix is correct but **load-bearing**: it
makes the templates usable through TerminalAdmin at all, but removes
even the "wrong password" speed-bump, so any escape vector in the
allowlist is *immediate* root.

**Test.** As `pm-tty-self`, `sudo apt-get update` returns without
prompting for a password. `sudo true` returns 0. `sudo -k && sudo true`
still returns 0 (ticket-cache state is irrelevant under NOPASSWD).

**Mitigation (required).** The LIMITED and FULL templates emit
`NOPASSWD:` on every command rule:

```diff
- %pm-sudo-{id} ALL=(ALL) /usr/bin/apt, /usr/bin/apt-get, /usr/bin/apt-cache, /usr/bin/dpkg
+ %pm-sudo-{id} ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/apt-cache, /usr/bin/dpkg
```

NOPASSWD applies only to the matching rule (sudoers grammar), so deny
rules don't need it.

**Status.** `GAP`. None of the existing templates use NOPASSWD.

### T2 — Editor escapes

**Threat.** `sudo vim` → `:!bash` → root shell. Same for `less`
(`!sh`), `more` (`!sh`), `emacs` (`M-x shell`), `nano --rcfile` chain,
`ed`, `ex`, `view`, `vimdiff`, `mc` (built-in shell), `nvim`. Under
NOPASSWD this is an unprompted, zero-friction root.

The current LIMITED template doesn't list any editors **and** doesn't
deny them. The implicit deny is correct only if (a) the allowlist
never grows, (b) no operator-installed binary lands at an
allowlisted path. Neither holds — the package-management allowlist
entries can install editors at `/usr/bin/vim` etc., and an admin
adding an editor to a CUSTOM template would silently break the
property.

**Test.** As the operator, run `sudo vim /etc/hosts` and attempt
`:!id`. The call must be rejected by sudoers before vim starts.
Repeat for each editor. Repeat via symlink: `ln -s $(which vim) ~/notvim
&& sudo ~/notvim /etc/hosts` — sudoers resolves symlinks
([sudoers(5)]), so the resolved-path deny still catches it.

**Mitigation (required).** A `!`-deny block in the LIMITED template:

```
%pm-sudo-{id} ALL=(ALL) !/usr/bin/vim, !/usr/bin/vi, \
    !/usr/bin/vimdiff, !/usr/bin/view, !/usr/bin/nvim, \
    !/usr/bin/emacs, !/usr/bin/emacsclient, \
    !/usr/bin/nano, !/bin/nano, \
    !/usr/bin/less, !/usr/bin/more, !/usr/bin/most, \
    !/usr/bin/ed, !/usr/bin/ex, \
    !/usr/bin/mc, !/usr/bin/joe, !/usr/bin/jed
```

**Status.** `GAP`. Add to `generateLimitedSudoConfig`.

### T3 — Shell spawns

**Threat.** `sudo sh`, `sudo bash -i`, `sudo zsh`, `sudo dash`,
`sudo -s`, `sudo -i`, `sudo env bash`. `sudo -s`/`-i` honor sudoers
`!` rules on the resolved shell path; `/usr/bin/env` is the
necessary extra deny because `sudo env bash` resolves via PATH.

**Test.** As operator: `sudo sh`, `sudo bash`, `sudo zsh`, `sudo
dash`, `sudo -i`, `sudo -s`, `sudo /bin/sh`, `sudo /usr/bin/env bash`,
`sudo SHELL=/bin/bash -s`. Each rejected.

**Mitigation (required).**

```
%pm-sudo-{id} ALL=(ALL) !/bin/sh, !/bin/bash, !/bin/dash, \
    !/bin/zsh, !/bin/ksh, !/bin/csh, !/bin/tcsh, !/bin/fish, \
    !/usr/bin/sh, !/usr/bin/bash, !/usr/bin/zsh, !/usr/bin/dash, \
    !/usr/bin/ksh, !/usr/bin/csh, !/usr/bin/tcsh, !/usr/bin/fish, \
    !/usr/bin/env
```

Pin `Defaults env_reset` in the same fragment (the default, but
explicit defense against `SHELL=…` env propagation).

**Status.** `GAP`.

### T4 — Defaults block

**Threat.** Without `requiretty`, the operator can pipe non-TTY
input into a sudo'd allowlisted command — fine for `apt-get update`,
but the same trick lets `sudo journalctl --pager=cat` write to a
named pipe the operator controls, bypassing the TTY-stream
assumption that backs session audit. Without `env_reset`, the
operator preserves their PATH and `$LD_PRELOAD`/`$BASH_ENV`. Under
NOPASSWD, `timestamp_timeout` is largely moot, but `0` is the right
value: forces sudoers re-evaluation on every call so a fresh
revocation lands immediately.

**Test.** `echo "id" | sudo apt-get` must refuse (`requiretty`).
`LD_PRELOAD=/tmp/x.so sudo apt-get update` must run with `LD_PRELOAD`
unset (env_reset).

**Mitigation (required).** First lines of the LIMITED template:

```
Defaults requiretty
Defaults env_reset
Defaults !lecture
Defaults timestamp_timeout=0
```

`!lecture` skips the operator-confusing first-time prompt. We do
**not** add `log_input, log_output`: terminal-session keystrokes are
already audited via the existing TerminalAuditChunk pipeline, and
duplicating into local sudo-io files would create files the
operator could later starve. Session audit is the single source.

**Status.** `GAP`. The current template has no `Defaults` block.

### T5 — Persistence beyond revocation

**Threat.** A Limited session can use **allowlisted** commands to
plant artifacts that survive removal from the group:

- `sudo apt-get install backdoor-package` → planted binary.
- `sudo systemctl enable evil.timer` → enabled timer.
- `sudo at now + 1 hour <<<'curl ...'` → deferred shell.
- `sudo crontab -u root -e` → editor (T2 catches the editor, but
  `crontab -l/-r` doesn't need an editor).
- `sudo dpkg-divert --add /usr/bin/legit /usr/bin/operator-controlled`
  → diversion.

Fails L4 over time.

**Test.** Run each above. Revoke. Inspect:

1. Package installed during the session is captured in audit and
   retained for admin review.
2. Enabled unit produces a `TerminalSessionEnabledUnit` audit
   record (added in #70).
3. No `at`/`crontab` jobs scheduled by the operator persist.

**Mitigation (required).**

```
%pm-sudo-{id} ALL=(ALL) !/usr/bin/at, !/usr/bin/atq, !/usr/bin/atrm, \
    !/usr/bin/batch, !/usr/bin/crontab, \
    !/usr/sbin/dpkg-divert, !/usr/bin/dpkg-divert, \
    !/usr/bin/update-alternatives, !/usr/sbin/update-alternatives
```

Package installs and unit enables stay allowed (operators need them
to do their jobs). The acceptance shape is **audit-and-review**, not
prevent — the existing terminal-input audit already captures the
keystrokes, so admin can reconstruct what was done.

**Status.** `GAP` for the deny lines. Audit retention is already
`MITIGATED` by the terminal_sessions table.

### T6 — Revocation lifecycle

**Threat.** Removing `TerminalAdminLimited` today would leave:

- The `pm-tty-<user>` membership in `pm-sudo-<actionID>` until the
  resolution layer re-runs and the agent processes the updated
  AdminPolicy action.
- Any **in-flight** sudo'd process from before revocation. Sudo
  doesn't kill children when the sudoers file is rewritten.
- The operator's open PTY (governed by `StartTerminal`, not by
  this ADR — admins who need immediate cutoff revoke `StartTerminal`
  or use the existing terminal-session admin UI to kill the session
  directly).

**Test.** Operator opens a session, runs `sudo journalctl -f` (an
allowlisted long-running command). Admin revokes
`TerminalAdminLimited`. Within the resolution-fanout interval:

1. `getent group pm-sudo-<actionID>` does NOT contain `pm-tty-<user>`.
2. A new `sudo apt-get update` invocation fails with
   `pm-tty-<user> is not in the sudoers file` (NOPASSWD reevaluated
   per call due to T4's `timestamp_timeout=0`).
3. The in-flight `sudo journalctl -f` **continues** until the
   operator's PTY is closed (acceptable — see Consequences).
4. The audit pipeline records a `TerminalAdminMembershipRevoked`
   event with the session id + actor user id.

**Mitigation (required).**

**Server side (resolution).** When the user loses the permission,
the LIMITED system action's `users` list is recomputed (intersection
of `TerminalAdminLimited` holders × scope) and the action's
`UpdatedActionParams` event fires. The existing per-device delivery
re-syncs.

**Agent side.** No new code — the existing `syncGroupMembers`
([`agent/internal/executor/sudo.go:107`](../../../agent/internal/executor/sudo.go#L107))
diffs the desired vs. current `pm-sudo-<id>` membership and calls
`gpasswd -d` for removed users.

**Server-side audit.** New event type `TerminalAdminMembershipRevoked`
emitted alongside the action update for traceability.

**Status.** Mostly `MITIGATED` (existing `syncGroupMembers` does the
gpasswd dance). **GAP** is the audit event emission.

### T6.GAP-A — Over-revocation safety

A user can hold both `TerminalAdminLimited` and `TerminalAdminFull`
on different scopes. Revoking Limited must NOT remove their Full
membership. The resolution layer must compute "which actions does
this user belong to on this device" as an **intersection of
(permission × scope)**, materialized as two separate `users` lists
(one per system action). Revoking one updates only its action's
list.

This is **GAP** until the resolution layer's
`TerminalAdminLimited` / `TerminalAdminFull` derivation is written.

## What "Limited" actually means (acceptance)

After T1-T6, **Limited** is:

> Membership in the system-managed `system:terminal-admin-limited`
> AdminPolicy action whose generated sudoers fragment is
> **deny-by-default**, contains only **resolved absolute paths** to
> binaries that, per documented behavior and by audit, do not
> provide escape vectors to arbitrary commands or interactive
> shells, runs **NOPASSWD** for the allowlist, denies all editors
> and shells and persistence vectors (at/crontab/dpkg-divert/
> update-alternatives) explicitly, with `requiretty` and `env_reset`
> pinned; whose keystrokes are recorded by the existing terminal
> session audit pipeline tagged with the human user; and whose
> **revocation** removes the operator's `pm-tty-*` from the group
> on next resolution fan-out, after which any new sudo call fails
> (in-flight elevated commands are allowed to complete).

Any drift toward `ALL=(ALL) ALL`, any editor in the allowlist, any
shell binary, or removal of NOPASSWD from a rule that was previously
NOPASSWD means **the effective grant is Full**, not Limited.

## What "Full" actually means

`TerminalAdminFull` is membership in the `system:terminal-admin-full`
action. Its fragment is unchanged from
[`generateFullSudoConfig`](../../../agent/internal/executor/sudo.go#L147)
**plus NOPASSWD**:

```
%pm-sudo-{id} ALL=(ALL:ALL) NOPASSWD: ALL
```

The threats above apply identically — audit pipeline, revocation,
tamper resistance — but T2/T3/T5 deny rules are absent because Full
is unrestricted by definition. Granting Full is a deliberate
control-plane decision; the agent doesn't try to limit what root
can do.

## Decision

- ADR adopted as the **acceptance contract** for [#70](https://github.com/manchtools/power-manage-server/issues/70).
- #70's PR may not merge while any `GAP` marker above is unresolved.
- **Two new permissions** land in
  [`server/internal/auth/permissions.go`](../../../server/internal/auth/permissions.go):
  `TerminalAdminLimited` and `TerminalAdminFull`. They do **not** imply
  `StartTerminal` (#7 Model Y, 2026-06-10) — the sudo cohort is driven
  by `TerminalAdmin*` alone, while `StartTerminal` independently drives
  the `pm-tty` account. A holder without `StartTerminal` gets the sudo
  policy listed but inert (no account), which the agent SKIPs
  gracefully.
- **Two new system-managed AdminPolicy actions** delivered the same
  way the existing `system:tty-user:*` actions are delivered — one
  for LIMITED, one for FULL. Their `users` list is computed by a
  new `SystemActionManager` method that mirrors `syncTtyUserAction`.
- **Template polish** in
  [`agent/internal/executor/sudo.go`](../../../agent/internal/executor/sudo.go):
  NOPASSWD on all rules, deny block for editors/shells/persistence
  vectors, Defaults block (`requiretty`, `env_reset`,
  `timestamp_timeout=0`, `!lecture`).
- The five threat sections become **executable regression tests**:
  - `agent/internal/executor/sudo_integration_test.go` — sudoers
    behavior on real distros (T1, T2, T3, T4, T5).
  - `server/internal/api/terminal_admin_resolution_test.go` —
    intersection of (permission × scope), audit emission on
    revocation (T6, T6.GAP-A).

### Account lock and session activation are separate domains (invariant)

Two distinct pieces of `pm-tty-*` account state are deliberately **not**
coupled, and must stay that way:

- **Session activation = the login shell.** The agent flips the shell
  `nologin` → `/bin/bash` at session start and back to `nologin` at
  session end (and on agent shutdown). This is ephemeral, session-scoped
  state the agent owns outright; it is the per-session gate and is not
  part of any action's desired state.
- **Account lock (`!`) = the disabled/offboarded policy state.** The
  shadow lock is driven by `UserParams.Disabled` (from the user's
  offboarding/disable status) and reconciled by the USER action
  (`desiredAccountLocked == params.Disabled`; sdk #259 / agent #158).

**Why they must not be coupled — the offboarding guarantee.** When a
user is offboarded (disabled), their `pm-tty-*` account is **locked**,
and the agent's terminal-start gate refuses a locked account
(`terminal.go`: `if info.Locked → "tty user is disabled"`). This is a
load-bearing security property: a disabled user loses terminal access
**under all circumstances** — even if they somehow mint or replay a
valid TTY token, the agent still denies the session because the account
is locked. If the lock were instead toggled per session (unlock on
start, lock on end, like the shell), that guarantee would break: a
session-scoped unlock could readmit an offboarded user, and the reconcile
(which drives the lock from `Disabled`) would fight the session toggle.
The lock therefore has exactly one meaning — "this user is disabled" —
and session lifecycle never touches it.

**Corollary — locking between sessions buys no security and is refused.**
The account is reachable only via the agent's root setuid opener, which
ignores the shadow lock, the `nologin` shell, and the (absent) password;
a non-root local user is already blocked by the passwordless `*`. So
re-locking an *enabled* account between sessions adds no OS-level defense
(the real gate is the server-side `StartTerminal` authorization + the
device-local `tty.enabled` flag), while it *would* re-break the next
session (the start gate refuses `!`). Enabled accounts rest at `*`
between sessions by design; only disabled/offboarded ones sit at `!`.

## Consequences

### In-flight commands continue after revocation (intentional)

The existing AdminPolicy/sudoers model does not kill running
processes when a sudoers fragment changes. Closing this would
require a per-revocation `pkill -u pm-tty-<user>` step that races
with legitimate long-running operator workflows (a `sudo apt-get
upgrade` mid-package mustn't die just because the admin tweaked an
unrelated scope).

The accepted shape: **revoke = no new sudos**, and if the admin
needs immediate cutoff of the operator's *session*, they use the
existing `StopTerminal` / `TerminateTerminalSession` admin path,
which closes the PTY and SIGHUP's its children — including any
in-flight sudo'd command. This is documented surface, not a gap.

### Locks us in

- **The five regression tests above** must pass on every supported
  distro family (Debian/Ubuntu, RHEL/Fedora, Arch, Alpine,
  openSUSE). Adding a new distro to the support matrix means
  re-running them, since editor/shell paths differ
  (`/usr/bin/vim` vs `/bin/vi`, etc.).
- **NOPASSWD is now load-bearing**. Any future template that
  removes NOPASSWD without re-enabling password-bearing pm-tty
  accounts will silently break TerminalAdmin (operators stop
  being able to sudo). Pin in test.

### Doesn't address

- **Kernel exploits** via patched-but-vulnerable allowlisted
  binaries. Mitigated by patch policy.
- **Malicious control-plane admin.** RBAC limits who can grant
  Full; this ADR limits what Limited means once granted.
- **Insider with prior root** via a separate, unmanaged path. The
  Limited sudoers fragment is irrelevant if the operator already
  has root. Defended by host hygiene.

### Alternatives considered (and rejected)

- **Per-operator sudoers fragment** instead of one shared
  group-driven fragment. Pros: per-operator audit (already
  provided by the existing session audit pipeline). Cons: N files
  per device × M devices to keep in sync; allowlist updates
  cascade to N×M writes. The group-driven path piggy-backs on the
  existing AdminPolicy primitive — single template per access
  level, member-list diff per device.
- **Custom audit forwarder per session.** Considered designing an
  off-box sudo-io forwarder. Rejected: the existing
  TerminalAuditChunk pipeline already captures keystrokes off-box
  with the human user attribution; a parallel forwarder would
  duplicate work and create a second tamper surface.
- **Replace sudo with a custom setuid wrapper.** Tempting (exact
  constraints) but operators expect sudo and a new setuid binary
  is its own attack surface.

## Open questions for #70 implementation

1. **Permission naming** — `TerminalAdminLimited` /
   `TerminalAdminFull` matches the issue. Alternatives:
   `RemoteShellLimited` / `RemoteShellFull`. Defer to #70 PR.
2. **DOAS counterpart** — `PRIVILEGE_BACKEND_DOAS` is supported by
   the action proto already. #70 ships SUDO only; DOAS follows
   once the doas template gets the same hardening as sudo. Filed
   as a follow-up.
3. **Resolution fan-out latency under revocation** — Asynq priority
   push to online devices via the existing terminal bidi stream,
   or accept "next heartbeat"? Default: next heartbeat for offline
   devices, opportunistic push for devices with active sessions
   (admin-driven `StopTerminal` is the immediate-cutoff path).

## References

- [`server/internal/api/system_actions.go:392-466`](../../../server/internal/api/system_actions.go#L392) — `syncTtyUserAction`; the new TerminalAdmin actions mirror this.
- [`agent/internal/executor/sudo.go:120-141`](../../../agent/internal/executor/sudo.go#L120) — `removeSudoPolicy` (handles member removal via `gpasswd`).
- [`agent/internal/executor/sudo.go:147-193`](../../../agent/internal/executor/sudo.go#L147) — `generateFullSudoConfig` + `generateLimitedSudoConfig`; the templates we polish.
- [`agent/internal/handler/terminal.go:189-394`](../../../agent/internal/handler/terminal.go#L189) — terminal session lifecycle; shell-flip on session open.
- [`server/internal/control/inbox_worker.go:929-960`](../../../server/internal/control/inbox_worker.go#L929) — `handleTerminalAuditChunk`; existing terminal input audit with human UserID.
- [`sdk/proto/pm/v1/actions.proto:616-643`](../../../sdk/proto/pm/v1/actions.proto#L616) — `AdminPolicyParams` schema (reused).
- [`server/internal/auth/permissions.go:204`](../../../server/internal/auth/permissions.go#L204) — `StartTerminal`; the new permissions sit alongside it.
- [#70](https://github.com/manchtools/power-manage-server/issues/70) — TerminalAdmin Limited / Full.
- [#7](https://github.com/manchtools/power-manage-server/issues/7) — scoped device-group RBAC (paired).
- [#321](https://github.com/manchtools/power-manage-server/issues/321) — this ADR's tracking issue.
