package doctor

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// placeholderRe matches the default/placeholder secret values an operator is
// meant to replace. The `change[_-]?me.*` arm is a PREFIX match so `CHANGE_ME`,
// `CHANGE_ME_NOW`, `changeme123` all flag — but a strong secret that merely
// contains the substring (e.g. `Sup3r...CHANGE_ME...`) does not. The rest are
// whole-value placeholders. Case-insensitive.
var placeholderRe = regexp.MustCompile(`(?i)^(change[_-]?me.*|changethis.*|placeholder|example|secret|password|test)$`)

// secretSpec is one tracked secret env var and its minimum acceptable length.
type secretSpec struct {
	key    string
	minLen int
}

// trackedSecrets are the secret-bearing vars the doctor judges. Names reflect the
// real deployment: the CONTROL_* vars the Control process reads, plus the
// compose-level `.env` names (POSTGRES_PASSWORD / VALKEY_PASSWORD) an operator
// edits. The Postgres password embedded in CONTROL_DATABASE_URL is judged
// separately (it has no standalone var here).
var trackedSecrets = []secretSpec{
	{"CONTROL_JWT_SECRET", 32},     // ≥32 bytes decoded; a <32-char string is definitely too short
	{"CONTROL_ENCRYPTION_KEY", 64}, // hex of 32 bytes
	{"PM_TASK_SIGNING_KEY", 64},    // hex of 32 bytes
	{"CONTROL_VALKEY_PASSWORD", 12},
	{"VALKEY_PASSWORD", 12},
	{"POSTGRES_PASSWORD", 12},
}

// SecretsCheck — weak/placeholder secrets (spec 15, criterion 4).
type SecretsCheck struct{}

func (SecretsCheck) ID() string { return "secrets" }

func (c SecretsCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	var findings []Finding
	judge := func(name, val string, minLen int) {
		if val == "" { // absence handled by the per-var required checks, not here
			return
		}
		switch {
		case placeholderRe.MatchString(val):
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("%s is set to a placeholder value", name),
				"replace it with a strong random secret"))
		case len(val) < minLen:
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("%s is shorter than the %d-character minimum", name, minLen),
				"regenerate it at full strength"))
		}
	}
	for _, s := range trackedSecrets {
		judge(s.key, env.Get(s.key), s.minLen)
	}
	// The DB password rides inside the DSN.
	judge("CONTROL_DATABASE_URL (password)", dsnPassword(env.Get("CONTROL_DATABASE_URL")), 12)

	if len(findings) == 0 {
		return []Finding{ok(c.ID(), "no placeholder or too-short secrets detected")}, nil
	}
	return findings, nil
}

// EncryptionKeyCheck — at-rest encryption is mandatory (spec 15, criterion 5).
// The historical CONTROL_ENCRYPTION_KEY_REQUIRED=false opt-out was removed; a
// missing key means Control will not boot.
type EncryptionKeyCheck struct{}

func (EncryptionKeyCheck) ID() string { return "encryption_key" }

func (c EncryptionKeyCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	if strings.TrimSpace(env.Get("CONTROL_ENCRYPTION_KEY")) == "" {
		return []Finding{crit(c.ID(),
			"CONTROL_ENCRYPTION_KEY is not set — at-rest encryption is mandatory and Control will not boot without it",
			"set CONTROL_ENCRYPTION_KEY to a 32-byte hex key")}, nil
	}
	return []Finding{ok(c.ID(), "at-rest encryption key is configured")}, nil
}

// CORSCheck — credentialed wildcard origin (spec 15, criterion 8).
type CORSCheck struct{}

func (CORSCheck) ID() string { return "cors" }

func (c CORSCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	for _, o := range strings.Split(env.Get("CONTROL_CORS_ORIGINS"), ",") {
		if strings.TrimSpace(o) == "*" {
			return []Finding{crit(c.ID(),
				"CONTROL_CORS_ORIGINS allows all origins (*)",
				"list explicit origins; the runtime rejects a credentialed wildcard (ADR 0008)")}, nil
		}
	}
	return []Finding{ok(c.ID(), "CORS is not configured allow-all")}, nil
}

// PortsCheck — internal mTLS listener bound to all interfaces (spec 15, criterion 9).
type PortsCheck struct{}

func (PortsCheck) ID() string { return "ports" }

func (c PortsCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	addr := env.Get("CONTROL_INTERNAL_LISTEN_ADDR")
	if addr == "" {
		addr = ":8082" // documented default
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port shaped — report as info rather than fail the suite.
		return []Finding{info(c.ID(), fmt.Sprintf("could not parse CONTROL_INTERNAL_LISTEN_ADDR %q", addr))}, nil
	}
	switch host {
	case "", "0.0.0.0", "::":
		return []Finding{warn(c.ID(),
			fmt.Sprintf("the internal mTLS listener binds all interfaces (port %s)", port),
			"restrict it to the internal network/interface or front it with the gateway, and ensure the host firewall blocks the port from the public internet")}, nil
	case "127.0.0.1", "::1", "localhost":
		return []Finding{ok(c.ID(), "internal mTLS listener is bound to loopback")}, nil
	default:
		return []Finding{info(c.ID(), fmt.Sprintf("internal mTLS listener is bound to %s — verify it is not a public interface", host))}, nil
	}
}

// ImageTagCheck — floating IMAGE_TAG in a production deploy (spec 15, criterion 10).
type ImageTagCheck struct{}

func (ImageTagCheck) ID() string { return "image_tag" }

func (c ImageTagCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	tag := env.Get("IMAGE_TAG")
	if tag == "" {
		if !env.FromEnvFile {
			return []Finding{info(c.ID(), "IMAGE_TAG not found (no .env file inspected); cannot assess image pinning")}, nil
		}
		return []Finding{ok(c.ID(), "IMAGE_TAG not set to a floating tag")}, nil
	}
	if tag == "latest" || strings.HasSuffix(tag, "-rc") || tag == "latest-rc" {
		return []Finding{warn(c.ID(),
			fmt.Sprintf("IMAGE_TAG=%s is a floating tag", tag),
			"pin a versioned tag or image digest for reproducible, auditable deploys")}, nil
	}
	return []Finding{ok(c.ID(), fmt.Sprintf("IMAGE_TAG is pinned (%s)", tag))}, nil
}
