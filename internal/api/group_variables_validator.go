package api

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// Group-scoped variable validator (manchtools/power-manage-server#195,
// design #59). Per-type SET-time rules are applied here so an invalid
// payload never reaches the JSONB column. Defence-in-depth: the
// renderer (ticket C, #196) re-validates the rendered value against
// the destination field's existing validator (sdk/go/validate).
//
// The validator is intentionally pure (no DB, no encryption) so it's
// trivial to test and so per-type behaviour stays in one file. The
// handler runs encryption for SECRET-typed values AFTER validation.

// variableNameRE enforces the lowercase-only name grammar. Two admins
// typing the same logical name in different cases ("nginx_port" vs
// "Nginx_Port") cannot create ghost duplicates because the regex
// rejects the second form at SET time.
var variableNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// hostnameLabelRE is the RFC 1123 label regex (lowercase), optionally
// chained with dots for subdomains.
var hostnameLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// pathShellMetaChars catches characters that would let a rendered path
// value escape into shell-interpretation in any plausible destination
// sink. Covers $ ` ; | & ( ) < > \ newline NUL.
const pathShellMetaChars = "$`;|&()<>\\\n\x00"

// variableNameMaxLen mirrors the proto-side cap.
const variableNameMaxLen = 64

// stringMaxLen caps non-secret string variables at 1 KiB per design.
const stringMaxLen = 1024

// hostnameMaxLen is the RFC 1035 cap.
const hostnameMaxLen = 253

// secretMaxLen is the proto-declared upper bound for SECRET values.
// The validator only enforces the bound; encryption is the handler's
// responsibility AFTER validation succeeds.
const secretMaxLen = 4096

// ValidateVariable runs the full per-type validation pipeline on a
// pm.v1.Variable. Returns a connect.Error with code ErrValidationFailed
// on failure (per-field message in the body so the web UI can inline-
// validate); returns nil on success.
//
// The function does NOT encrypt the SECRET value — encryption is the
// handler's responsibility AFTER validation succeeds. Keeping
// validation pure means it's safe to run at multiple layers (handler,
// renderer, future server-side import) without dragging the encryptor
// through the call chain.
func ValidateVariable(ctx context.Context, v *pm.Variable) error {
	if v == nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, "variable is required")
	}
	if err := validateVariableName(v.GetName()); err != nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, err.Error())
	}
	if err := validateVariableValueByType(v); err != nil {
		return apiErrorCtx(ctx, ErrValidationFailed, connect.CodeInvalidArgument, err.Error())
	}
	return nil
}

// validateVariableName enforces the lowercase-only grammar and the
// length cap. Empty / over-cap / non-matching names are all rejected
// with a name-specific message.
func validateVariableName(name string) error {
	if name == "" {
		return fmt.Errorf("variable.name is required")
	}
	if len(name) > variableNameMaxLen {
		return fmt.Errorf("variable.name must be at most %d characters", variableNameMaxLen)
	}
	if !variableNameRE.MatchString(name) {
		return fmt.Errorf("variable.name must match ^[a-z][a-z0-9_]*$ (lowercase letters, digits, underscore; must start with a letter)")
	}
	return nil
}

// validateVariableValueByType dispatches per-type rules on the raw
// value string. Each rule returns an error keyed off the value field
// so the operator-visible diagnostic points at the right control in
// the web UI.
func validateVariableValueByType(v *pm.Variable) error {
	value := v.GetValue()
	switch v.GetType() {
	case pm.VariableType_VARIABLE_TYPE_UNSPECIFIED:
		return fmt.Errorf("variable.type is required")
	case pm.VariableType_VARIABLE_TYPE_STRING:
		return validateStringValue(value)
	case pm.VariableType_VARIABLE_TYPE_INT:
		return validateIntValue(value, v.GetIntMin(), v.GetIntMax())
	case pm.VariableType_VARIABLE_TYPE_BOOL:
		return validateBoolValue(value)
	case pm.VariableType_VARIABLE_TYPE_HOSTNAME:
		return validateHostnameValue(value)
	case pm.VariableType_VARIABLE_TYPE_PATH:
		return validatePathValue(value)
	case pm.VariableType_VARIABLE_TYPE_CHOICE:
		return validateChoiceValue(value, v.GetChoiceValues())
	case pm.VariableType_VARIABLE_TYPE_SECRET:
		return validateSecretValue(value)
	}
	return fmt.Errorf("variable.type %d is not a known VariableType", v.GetType())
}

func validateStringValue(value string) error {
	if len(value) > stringMaxLen {
		return fmt.Errorf("variable.value must be at most %d characters for VARIABLE_TYPE_STRING", stringMaxLen)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("variable.value must not contain control characters for VARIABLE_TYPE_STRING")
		}
		// Require printable ASCII — anything outside 0x20-0x7E rejects.
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("variable.value must contain only printable ASCII for VARIABLE_TYPE_STRING")
		}
	}
	return nil
}

func validateIntValue(value string, intMin, intMax int64) error {
	if value == "" {
		return fmt.Errorf("variable.value is required for VARIABLE_TYPE_INT")
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("variable.value must be a base-10 int64 for VARIABLE_TYPE_INT: %v", err)
	}
	// Bounds enforced only when at least one bound is non-zero.
	if intMin != 0 || intMax != 0 {
		if intMin > intMax {
			return fmt.Errorf("int_min (%d) must be <= int_max (%d)", intMin, intMax)
		}
		if n < intMin || n > intMax {
			return fmt.Errorf("variable.value %d out of range [%d, %d]", n, intMin, intMax)
		}
	}
	return nil
}

func validateBoolValue(value string) error {
	if value != "true" && value != "false" {
		return fmt.Errorf("variable.value must be exactly \"true\" or \"false\" for VARIABLE_TYPE_BOOL")
	}
	return nil
}

func validateHostnameValue(value string) error {
	if value == "" {
		return fmt.Errorf("variable.value is required for VARIABLE_TYPE_HOSTNAME")
	}
	if len(value) > hostnameMaxLen {
		return fmt.Errorf("variable.value must be at most %d characters for VARIABLE_TYPE_HOSTNAME", hostnameMaxLen)
	}
	if !hostnameLabelRE.MatchString(value) {
		return fmt.Errorf("variable.value must be an RFC 1123 hostname for VARIABLE_TYPE_HOSTNAME")
	}
	return nil
}

func validatePathValue(value string) error {
	if value == "" {
		return fmt.Errorf("variable.value is required for VARIABLE_TYPE_PATH")
	}
	if value[0] != '/' {
		return fmt.Errorf("variable.value must be an absolute path (start with /) for VARIABLE_TYPE_PATH")
	}
	// Reject any segment equal to "..". Splitting on '/' is the
	// straightforward way; empty segments (from leading slash or
	// "//") are tolerated here because they're not a traversal vector
	// on their own.
	for _, seg := range strings.Split(value, "/") {
		if seg == ".." {
			return fmt.Errorf("variable.value must not contain \"..\" path segments for VARIABLE_TYPE_PATH")
		}
	}
	if strings.ContainsAny(value, pathShellMetaChars) {
		return fmt.Errorf("variable.value must not contain shell metacharacters ($, `, ;, |, &, parens, <>, backslash, newline, NUL) for VARIABLE_TYPE_PATH")
	}
	// Reject whitespace separately. With the renderer substituting
	// values literally (no shell-quoting at render time), whitespace
	// in a path would split the rendered token into multiple shell
	// arguments — argument-injection-style behaviour even without any
	// metacharacter present. CR finding on PR #197.
	for _, r := range value {
		if unicode.IsSpace(r) {
			return fmt.Errorf("variable.value must not contain whitespace for VARIABLE_TYPE_PATH")
		}
	}
	return nil
}

func validateChoiceValue(value string, choices []string) error {
	if len(choices) == 0 {
		return fmt.Errorf("choice_values must be non-empty for VARIABLE_TYPE_CHOICE")
	}
	if value == "" {
		return fmt.Errorf("variable.value is required for VARIABLE_TYPE_CHOICE")
	}
	for _, c := range choices {
		if c == value {
			return nil
		}
	}
	return fmt.Errorf("variable.value %q not in choice_values", value)
}

func validateSecretValue(value string) error {
	if value == "" {
		return fmt.Errorf("variable.value is required for VARIABLE_TYPE_SECRET")
	}
	if len(value) > secretMaxLen {
		return fmt.Errorf("variable.value must be at most %d characters for VARIABLE_TYPE_SECRET", secretMaxLen)
	}
	return nil
}
