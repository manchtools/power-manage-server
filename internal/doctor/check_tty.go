package doctor

import (
	"context"
	"fmt"
	"strings"
)

// TerminalCheck validates the remote-terminal (TTY) plumbing the control relies
// on (spec 15). The failure mode it primarily catches is the one hit in the
// field: the gateway self-registers its Traefik routes — including the
// per-replica TTY HTTP router — into Valkey, and Traefik's Redis provider
// WATCHES that keyspace. But the watch only works if Valkey emits keyspace
// notifications; with them off (the Redis default), Traefik reads the keyspace
// once at boot and never sees a (re)deployed gateway's terminal route, so
// terminal WebSockets 404 with nothing obvious in any log. It also flags two
// config inconsistencies that silently break terminals.
type TerminalCheck struct{}

func (TerminalCheck) ID() string { return "terminal" }

func (c TerminalCheck) Run(ctx context.Context, env *Env) ([]Finding, error) {
	// Remote terminal is opt-in — the gateway only mints/serves sessions when the
	// public terminal URL template is set. Unset ⇒ disabled, nothing to check.
	if env.Get("GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE") == "" {
		return []Finding{info(c.ID(), "remote terminal disabled (GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE unset)")}, nil
	}

	var findings []Finding

	// Config: the gateway serves the terminal WebSocket on GATEWAY_WEB_LISTEN_ADDR.
	// Minting terminal URLs while that listener is off advertises sessions the
	// gateway cannot serve — the browser WebSocket just fails.
	if env.Get("GATEWAY_WEB_LISTEN_ADDR") == "" {
		findings = append(findings, warn(c.ID(),
			"GATEWAY_PUBLIC_TERMINAL_URL_TEMPLATE is set but GATEWAY_WEB_LISTEN_ADDR is empty — the gateway will not serve terminal WebSockets",
			"set GATEWAY_WEB_LISTEN_ADDR (e.g. :8443) on the gateway and recreate the container"))
	}

	// Config: the TTY host must differ from the gateway mTLS host, or Traefik's
	// TCP-passthrough router for the gateway SNI shadows the TTY HTTP router on
	// the shared :443 entrypoint.
	ttyHost := firstNonEmptyVar(env, "GATEWAY_TRAEFIK_TTY_HOST", "GATEWAY_TTY_DOMAIN", "GATEWAY_DOMAIN")
	gwHost := firstNonEmptyVar(env, "GATEWAY_TRAEFIK_MTLS_HOST", "GATEWAY_DOMAIN")
	if ttyHost != "" && ttyHost == gwHost {
		findings = append(findings, warn(c.ID(),
			"the TTY host equals the gateway mTLS host — Traefik's TCP-passthrough router shadows the terminal HTTP router on the shared SNI",
			"set a dedicated GATEWAY_TTY_DOMAIN distinct from GATEWAY_DOMAIN"))
	}

	// Live: Valkey keyspace notifications must be on so Traefik can WATCH the
	// gateway's self-registered routes. Only relevant when the gateway self-
	// registers via the Redis KV provider (the default; disabled only by an
	// explicit GATEWAY_TRAEFIK_SELF_REGISTER=false).
	if env.Get("GATEWAY_TRAEFIK_SELF_REGISTER") != "false" {
		skip, proceed := cacheReady(ctx, c, env)
		if !proceed {
			return append(findings, skip...), nil
		}
		notif, err := env.Cache.KeyspaceNotifications(ctx)
		if err != nil {
			// Valkey is reachable (cacheReady pinged it) but CONFIG GET failed —
			// the check could not run, not a clean pass.
			return nil, fmt.Errorf("read Valkey notify-keyspace-events: %w", err)
		}
		if !keyspaceNotificationsSufficient(notif) {
			f := warn(c.ID(),
				"Valkey keyspace notifications are off — Traefik cannot watch the gateway's self-registered routes, so a (re)deployed gateway's terminal route is not picked up until Traefik is restarted (terminal WebSockets 404)",
				`set notify-keyspace-events to "KEA" in valkey.conf, then restart Valkey and Traefik`)
			f.Detail = fmt.Sprintf("notify-keyspace-events=%q", notif)
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []Finding{ok(c.ID(), "remote terminal config consistent; Valkey keyspace notifications enabled for Traefik route watching")}, nil
	}
	return findings, nil
}

// keyspaceNotificationsSufficient reports whether notify-keyspace-events is
// configured enough for Traefik's Redis provider to WATCH the KV: it needs a
// channel flag (K=keyspace or E=keyevent) AND event classes (A=all, or at least
// generic 'g'). Empty (the Redis default) is the common broken case.
func keyspaceNotificationsSufficient(s string) bool {
	return strings.ContainsAny(s, "KE") && strings.ContainsAny(s, "Ag")
}

// firstNonEmptyVar returns the first non-empty env value among keys.
func firstNonEmptyVar(env *Env, keys ...string) string {
	for _, k := range keys {
		if v := env.Get(k); v != "" {
			return v
		}
	}
	return ""
}
