package doctor

import (
	"context"
	"fmt"
	"net/url"
)

// TerminalCheck validates the remote-terminal (TTY) plumbing (spec 15).
//
// Every variable this check previously read (GATEWAY_PUBLIC_TERMINAL_URL_
// TEMPLATE, GATEWAY_WEB_LISTEN_ADDR, GATEWAY_TTY_DOMAIN, GATEWAY_TRAEFIK_*)
// belonged to the gateway. After spec 41 none of them are set on any
// deployment, so the check took its "terminal disabled" branch every time and
// reported an INFO — a green result that told the operator terminals were off
// while they were on. It could not fail, which is the one thing a check must be
// able to do.
//
// The terminal is now served by control's own PUBLIC listener at /terminal and
// reached through the same Traefik HTTP router as the web UI. That leaves three
// ways for it to break, and this check covers each:
//
//  1. The URL's host is the agent host. Traefik dispatches :443 by SNI and the
//     agent host is a TCP-passthrough router, so a terminal URL pointing there
//     hands the browser straight to the mTLS listener, which demands a client
//     certificate no browser has.
//  2. The scheme is not wss. The browser dials this verbatim.
//  3. The URL is set but Valkey is not configured. control mounts the bridge
//     only when the terminal token store exists, so StartTerminal would
//     authorise sessions against a path that 404s.
type TerminalCheck struct{}

func (TerminalCheck) ID() string { return "terminal" }

func (c TerminalCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	// Remote terminal is opt-in: control mints session URLs only when the
	// public terminal URL is set, and returns Unavailable otherwise.
	terminalURL := env.Get("CONTROL_TERMINAL_URL")
	if terminalURL == "" {
		return []Finding{info(c.ID(), "remote terminal disabled (CONTROL_TERMINAL_URL unset)")}, nil
	}

	var findings []Finding

	tu, err := url.Parse(terminalURL)
	if err != nil {
		f := warn(c.ID(),
			"CONTROL_TERMINAL_URL is not a parseable URL — every terminal session hands the browser this value verbatim",
			"set CONTROL_TERMINAL_URL to wss://<control-domain>/terminal")
		f.Detail = fmt.Sprintf("parse error: %v", err)
		return append(findings, f), nil
	}

	if tu.Scheme != "wss" {
		findings = append(findings, warn(c.ID(),
			fmt.Sprintf("CONTROL_TERMINAL_URL uses scheme %q — the browser opens this as a WebSocket and only wss is served over TLS", tu.Scheme),
			"set CONTROL_TERMINAL_URL to wss://<control-domain>/terminal"))
	}

	// The collision that matters now is with the AGENT host, not with a second
	// terminal host. Traefik's TCP-passthrough router for the agent SNI wins
	// over any HTTP router sharing that name, so a terminal URL on the agent
	// host reaches control's mTLS listener instead of /terminal.
	if agentURL := env.Get("CONTROL_AGENT_URL"); agentURL != "" && tu.Hostname() != "" {
		if au, err := url.Parse(agentURL); err == nil && au.Hostname() == tu.Hostname() {
			findings = append(findings, warn(c.ID(),
				"CONTROL_TERMINAL_URL is on the same host as CONTROL_AGENT_URL — Traefik passes that SNI through to the agent mTLS listener, so the browser's WebSocket is asked for a client certificate and fails",
				"point CONTROL_TERMINAL_URL at the control/web domain (CONTROL_DOMAIN), not the agent domain"))
		}
	}

	// control mounts the WebSocket bridge only when the Valkey-backed terminal
	// token store is available. Without it StartTerminal still authorises the
	// session and mints a token, and the browser then 404s on /terminal.
	if env.Get("CONTROL_VALKEY_ADDR") == "" {
		findings = append(findings, warn(c.ID(),
			"CONTROL_TERMINAL_URL is set but CONTROL_VALKEY_ADDR is empty — control does not mount the terminal bridge without the token store, so sessions are authorised against a path that does not exist",
			"set CONTROL_VALKEY_ADDR (e.g. valkey:6379) and recreate the control container"))
	}

	if len(findings) == 0 {
		return []Finding{ok(c.ID(), "remote terminal reachable: wss URL on the web host, bridge mounted")}, nil
	}
	return findings, nil
}
