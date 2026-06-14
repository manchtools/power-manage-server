// Package api file action_validators.go — Create / Update request
// validators, extracted from action_handler.go (audit F005). All
// validators take a context for log/error correlation and return a
// connect.Error so handlers can return them straight through.
//
// The per-oneof params validation that used to be three near-identical
// switch tables (Create / Update / inline) collapsed into one
// validateParamsMsg keyed off actionparams.ExtractParamsMsg — the
// reflective oneof walk — with the two type-specific extras (shell
// script-choice, agent-update arch/HTTPS) the only remaining special
// cases.
package api

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// validateParamsMsg runs the struct-tag validation plus the two
// type-specific extra checks for a params sub-message extracted from a
// Create / Update / inline request. A nil message (no params oneof set)
// is a no-op — the outer handler decides whether absent params is an
// error for the declared type. This is the single source the Create,
// Update, and inline validators share, so a rule added for one applies
// to all three (the inline path "cannot do anything a Create-path
// action cannot").
//
//   - ShellParams: struct-tag validation THEN the "at least one of
//     script / detection_script" rule.
//   - AgentUpdateParams: validateAgentUpdateParams (which runs its own
//     struct-tag validation plus the arch + HTTPS-URL checks).
//   - everything else: struct-tag validation only.
func validateParamsMsg(ctx context.Context, msg proto.Message) error {
	if msg == nil {
		return nil
	}
	switch p := msg.(type) {
	case *pm.ShellParams:
		if err := Validate(ctx, p); err != nil {
			return err
		}
		return validateShellScriptChoice(ctx, p)
	case *pm.AgentUpdateParams:
		return validateAgentUpdateParams(ctx, p)
	case *pm.AppInstallParams:
		return validateAppInstallParams(ctx, p)
	default:
		return Validate(ctx, msg)
	}
}

// isLowerHex64 reports whether s is exactly 64 lowercase hex characters —
// the canonical SHA-256 form. The struct-tag `hexadecimal` validator also
// accepts UPPERCASE, so this explicit check pins the lowercase form the
// agent's comparison and the design expect (defense in depth: the agent
// compares case-insensitively, but the control plane stores canonical).
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validateAppInstallParams enforces, for deb/rpm/appimage download-and-
// install actions, that the url is https and a 64-lowercase-hex
// checksum_sha256 is present (WS7 #2 — mandatory integrity; without it the
// only authenticity is TLS to a possibly-compromised origin). The
// required-checksum + valid-url tags run via Validate; the https + lower-
// hex rules are the explicit additions.
func validateAppInstallParams(ctx context.Context, p *pm.AppInstallParams) error {
	if err := Validate(ctx, p); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToLower(p.Url), "https://") {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "url must use HTTPS")
	}
	if !isLowerHex64(p.ChecksumSha256) {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "checksum_sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// validateCreateActionParams validates the params oneof of a CreateActionRequest.
func validateCreateActionParams(ctx context.Context, req *pm.CreateActionRequest) error {
	return validateParamsMsg(ctx, actionparams.ExtractParamsMsg(req))
}

// validateShellScriptChoice enforces the Create-time rule that a
// shell action must specify at least one of `script` or
// `detection_script` — otherwise the action is a no-op that signs
// cleanly and turns into a mystery when operators can't figure out
// why nothing ran. Applied anywhere a ShellParams is accepted
// (Create, Update params, inline Dispatch).
func validateShellScriptChoice(ctx context.Context, p *pm.ShellParams) error {
	if p == nil {
		return nil
	}
	if p.Script == "" && p.DetectionScript == "" {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one of script or detection_script is required")
	}
	return nil
}

// validateInlineAction validates an inline Action proto on a
// DispatchAction request. The non-inline DispatchAction path pulls
// the action by ID from the DB, which has already been validated at
// Create/Update time; inline actions skip that lookup and would
// otherwise reach the agent unvalidated, potentially signing a
// malformed or oversized payload that the agent silently drops.
//
// Every oneof branch mirrors validateCreateActionParams — including
// the shell "at least one of script or detection_script" rule —
// so an inline dispatched action cannot do anything a Create-path
// action cannot.
//
// Beyond the per-oneof params validation, this function enforces the
// outer Action invariants that the by-ID dispatch path gets for free
// from the Create/Update gate:
//
//   - Type is non-unspecified.
//   - TimeoutSeconds is in [0, 3600].
//   - Schedule, if present, validates.
//   - Type matches the populated params oneof — a caller cannot say
//     `Type=USER` while sending an Ssh oneof and have the dispatch
//     path treat it as a USER action with garbage params.
func validateInlineAction(ctx context.Context, action *pm.Action) error {
	if action == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action is required")
	}
	if action.Type == pm.ActionType_ACTION_TYPE_UNSPECIFIED {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "action type is required")
	}
	if action.TimeoutSeconds < 0 || action.TimeoutSeconds > 3600 {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "timeout_seconds must be between 0 and 3600")
	}
	if action.Schedule != nil {
		if err := Validate(ctx, action.Schedule); err != nil {
			return err
		}
	}

	params := actionparams.ExtractParamsMsg(action)
	if params == nil {
		// ACTION_TYPE_UPDATE has no params payload — that one
		// matches `nil` legitimately. Every other type must
		// carry a populated oneof.
		if action.Type == pm.ActionType_ACTION_TYPE_UPDATE {
			return nil
		}
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params are required")
	}
	if !actionparams.ParamsMatchType(action, action.Type) {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "inline_action params do not match action.Type")
	}
	return validateParamsMsg(ctx, params)
}

// validateUpdateActionParams validates the params oneof of an UpdateActionParamsRequest.
func validateUpdateActionParams(ctx context.Context, req *pm.UpdateActionParamsRequest) error {
	return validateParamsMsg(ctx, actionparams.ExtractParamsMsg(req))
}

// validateAgentUpdateParams checks that at least one arch is set and all URLs are HTTPS.
func validateAgentUpdateParams(ctx context.Context, p *pm.AgentUpdateParams) error {
	if err := Validate(ctx, p); err != nil {
		return err
	}
	if p.Amd64 == nil && p.Arm64 == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "at least one architecture (amd64 or arm64) must be specified")
	}
	for _, arch := range []*pm.AgentUpdateArch{p.Amd64, p.Arm64} {
		if arch == nil {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(arch.BinaryUrl), "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "binary_url must use HTTPS")
		}
		// WS7: integrity is required, but the operator chooses the source.
		// At least one of checksum_url (default — track "latest", verified
		// against the operator's checksum file) or expected_sha256 (an
		// exact pinned hash inside the CA-signed action) must be set, so an
		// update can never run with no integrity check at all.
		if arch.ChecksumUrl == "" && arch.ExpectedSha256 == "" {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "each architecture must set checksum_url or expected_sha256")
		}
		if arch.ChecksumUrl != "" && !strings.HasPrefix(strings.ToLower(arch.ChecksumUrl), "https://") {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "checksum_url must use HTTPS")
		}
		// When pinned, expected_sha256 is the CA-signed hash that overrides
		// the checksum file. Explicit 64-lowercase-hex check (the struct-tag
		// `hexadecimal` rule also accepts uppercase, which the canonical
		// stored form must not).
		if arch.ExpectedSha256 != "" && !isLowerHex64(arch.ExpectedSha256) {
			return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "expected_sha256 must be 64 lowercase hex characters")
		}
	}
	return nil
}
