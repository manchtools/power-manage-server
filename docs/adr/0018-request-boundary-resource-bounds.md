# 0018 — Resource bounds & timeouts at the request boundary

- Status: accepted
- Date: 2026-06-14
- Related: WS13 of the SECURITY_HARDENING_WORKPLAN (manchtools/power-manage-server#426);
  builds on WS11 (per-user authenticated-RPC rate limiting — ADR 0015) and WS5
  (bounded OIDC client, CORS production gate). #427 tracks the deferred indexer
  rebuild gate.

## Context

The request boundary had several unbounded resources an attacker (or a buggy
client) could exhaust: client-controlled deep pagination OFFSET, no request-body
size cap (pre-auth buffering), no DB statement timeout, no per-handler deadline,
unbounded gateway↔control proxy calls, and a full event-stream buffer during
rebuild. WS13 bounds them.

## Decision

- **Pagination offset ceiling (#3).** `parsePagination` caps the offset at
  `maxListOffset = 100_000` (the Search backbone's ceiling) and REJECTS a token
  past it with `CodeInvalidArgument`/`ErrInvalidPageToken` — no client can force
  a deep-OFFSET full-table scan; beyond the ceiling, list pages route through
  Search (server#84/#325).
- **Request-body size caps (#4).** `connect.WithReadMaxBytes` on every service
  handler: ControlService + InternalService at 8 MiB (generous for control-plane
  payloads incl. embedded action content), the gateway GatewayService at 4 MiB.
  An over-cap body is rejected with `CodeResourceExhausted` before the handler
  runs, closing pre-auth unbounded buffering (Login/Register are public).
- **DB statement_timeout + per-handler deadline (#10).** The pgx pool sets an
  application `statement_timeout` (30s, per-statement) plus explicit
  MaxConns/MaxConnLifetime; migrations run on a separate stdlib connection and
  are exempt. A unary `RequestDeadline` interceptor (30s) backstops the DB bound
  for non-DB blocking; streaming passes through; a shorter caller deadline wins.
- **Per-call proxy deadlines (#11).** Each gateway→control InternalService call
  derives a 15s `context.WithTimeout` — per-call, not a client-wide
  `http.Client.Timeout` that would also break the long-lived agent bidi stream.
  (The control→gateway terminate/list fan-out was already bounded in WS11.)
- **Streaming rebuild (#14).** `dispatchViaGoApplier` keyset-paginates the event
  replay in bounded batches (1000) instead of buffering the full matching stream;
  each batch's rows are closed before applying (pgx forbids a second query on a
  connection with a live result set) and the sequence_num cursor advances.
- **CORS (#13/#15).** Test coverage added; `Cookie` dropped from the allowed
  request headers (auth is Bearer-only). The credentialed-wildcard reflection was
  already removed in WS5 #7.

## Already covered (verified, not re-implemented)

- **Dyngroup evaluation rate-limit (#9):** the `Evaluate*`/`*Query` RPCs already
  match WS11's self-discovering `isExpensiveProcedure` and are gated per-user by
  the `Expensive` limiter in the auth interceptor — BEFORE the handler runs, so
  no whole-table load occurs on a rejected call.
- **Outbound OIDC timeout:** WS5 already builds OIDC discovery/JWKS with a
  bounded `*http.Client` (`oidcHTTPTimeout`) injected via `oidc.ClientContext`.

## Deferred

- **Indexer startup rebuild gate + Valkey lock + backoff (#12 → #427).** The
  destructive `FlushSearchData`+`Rebuild` on every indexer boot should be gated
  behind an index-present check and a `SET NX` lock. Proper verification needs a
  real RediSearch (`FT.INFO`/`FT.DROPINDEX`), which miniredis cannot provide; the
  redis-stack-server testcontainer swap is tracked under #319. Deferred so the
  change to a destructive index operation ships with real coverage.

## Consequences

- Operators paging beyond 100_000 rows get a clear `CodeInvalidArgument` (should
  use Search/filters). A request body over the per-service cap is rejected with
  `CodeResourceExhausted`. A single query over 30s is cancelled by Postgres.
- No new error codes or i18n keys: pagination reuses `ErrInvalidPageToken`,
  size/deadline are connect transport codes, rate-limit reuses WS11's.
