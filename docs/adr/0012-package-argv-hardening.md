# 0012 — Package/repository argv hardening: end-of-options + intent validation

- Status: accepted
- Date: 2026-06-14
- Related: manchtools/power-manage-sdk#88 (the argv-validation surface);
  manchtools/power-manage-agent#111 (agent adoption); the 2026-06-12 audits
  (WS8 of the SECURITY_HARDENING_WORKPLAN); ADR 0003 (action signing — actions
  are CA-signed); ADR 0005 (the gateway/relay is untrusted for origination);
  ADR 0011 (the operator-choice integrity posture this mirrors).

## Context

The agent runs as root and drives the system package managers. Several
package/repository actions passed **untrusted, action-supplied** values
straight onto a command line with no intent grammar and no end-of-options
separator:

- `RPM` install/remove derived the package name from `rpm -qp %{NAME}` on the
  downloaded `.rpm` and passed it to `rpm -q`/`rpm -e` unvalidated. A crafted
  `.rpm` can report a `%{NAME}` like `--eval=%{lua:os.execute('id')}`, which
  `rpm` would parse as an option/macro rather than a package operand.
- dnf/zypper GPG key refs were passed to `rpm --import <ref>` with no scheme or
  charset restriction and no `--`; `rpm --import` accepts `http://` (MITM of
  the trust anchor) and the `ext::` transport (which executes a command).
- dnf `baseurl` / zypper `url` / pacman `server` — where root packages are
  fetched — had no https enforcement, so a forged-but-unsigned config could
  point them at plaintext http.
- flatpak app-id/remote were passed to `flatpak install` as bare positionals;
  a value beginning with `-` (`--from=…`, `--sideload-repo=…`) is parsed as an
  option.
- The repository-field injection test pinned a stale, hand-maintained subset
  of fields, so a newly-added proto field could silently ship without its
  config-injection (newline) guard.

Actions are CA-signed (ADR 0003), so this is not classic untrusted input — but
a malformed or compromised-origin action must not be able to smuggle options,
substitute a payload, or inject config directives.

## Decision

1. **Intent validation at the SDK boundary** (`sdk/go/pkg`): new exported
   validators — `ValidateRpmPackageName`, `ValidateRepoBaseURL`,
   `ValidateGpgKeyRef`, `ValidateRemoteName` — each sourcing "valid" from
   intent (leading-alphanumeric names; https/file/abs-path key refs; https
   base URLs). They are mandatory at every argv boundary the agent owns.
2. **End-of-options everywhere** (`sdk/go/sys/exec.SeparatePositionals`): every
   untrusted operand is passed after an explicit `--`, so a value that slips
   past validation (or a future caller that forgets it) still cannot be
   reparsed as an option. Applies to `rpm -q/-e -- <name>`,
   `rpm --import -- <ref>`, and `flatpak install … -- <remote> <appId>`.
3. **MITM pinning** for `.rpm`/`.deb`/`.appimage`: https + a non-empty checksum
   is required, fail-closed, **before** any privileged filesystem remount or
   network round-trip (mirrors ADR 0011's `AppInstallParams.checksum_sha256`).
4. **HTTPS on repository base URLs** for dnf/zypper/pacman. **apt is exempt**:
   apt's security model is the gpg-signed `Release` file, so an http transport
   with a trusted key is a legitimate, long-standing configuration.
5. **Self-discovering field coverage**: the repository validator test
   reflection-walks every string field of every repo proto and fails closed if
   a field lacks the newline guard. The sole documented exclusion is
   `apt.gpg_key` — armored key *content* written verbatim to a file, where
   newlines are legitimate.

## Operator choice — `gpgcheck` is NOT a hard gate

The workplan floated refusing a dnf/zypper base URL when `gpgcheck=false`. We
**deliberately did not** add that refusal. Enforcing https closes the
transport-MITM (the actual finding); package-signature verification is a
separate layer and is the operator's call — exactly the posture ADR 0011 took
for `checksum_url`. A refusal would break legitimate internal-mirror
configurations (an https mirror the operator trusts, run with `gpgcheck=false`),
which are in active use. The decision is pinned by
`TestValidateRepositoryParams_AllowsOperatorChoiceGpgcheck` so it is not
silently reverted.

## Accepted risk

An https repository run with `gpgcheck=false` and no key installs root packages
verified only by TLS to the origin — no package-signature check. This is an
accepted, operator-selected risk, identical in spirit to ADR 0011's default
`checksum_url` mode: the transport is verified, the action is CA-signed, and an
operator who wants more enables `gpgcheck` with a key (the grammar for which is
now enforced) or runs their own signed mirror.

## Consequences

- A forged/compromised-origin action can no longer inject options into rpm or
  flatpak, import a key over http or via `ext::`, or point a dnf/zypper/pacman
  base URL at plaintext http.
- Shared single-source validators (SDK) keep the agent and any future consumer
  from re-implementing (and drifting on) the grammar — the SDK-first/DRY rule.
- No web or server-handler change: these are agent-side `fmt.Errorf` surfaced
  in task results, not new Connect error codes, so no i18n/error-code registry
  entry is required.
