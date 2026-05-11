// Package template implements the server-side `{{ var.NAME }}`
// substitution pass for action params. Every templateable field on
// the wire-format Action proto is walked via protoreflect and its
// references are replaced with the resolved variable values before
// the Action leaves the server. The pipeline is intentionally
// no-context-aware-shell-quoting: values flow in literally, so the
// trust gate lives at the SET-time RBAC on the variable itself
// (handled in internal/api/group_variable_handler.go and
// internal/auth/permissions.go). See the design notes on
// manchtools/power-manage-server#59 for the rationale.
package template

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Renderer rewrites templateable string fields on an Action proto in
// place. A single Renderer is safe to share across goroutines; the
// per-call state is the resolved variable map produced by the
// Resolver.
type Renderer struct {
	resolver Resolver
}

// New constructs a Renderer backed by the given Resolver.
func New(resolver Resolver) *Renderer {
	return &Renderer{resolver: resolver}
}

// Resolver supplies the variable map for a given device. The
// production implementation lives in internal/api/template/resolver.go
// and reads variables from the device's device-group + user-group
// memberships (variables are exclusively a group concept; device
// labels do NOT participate in resolution); tests substitute a
// static map.
type Resolver interface {
	Resolve(ctx context.Context, deviceID string) (Variables, error)
}

// Variables is the resolved name → value map at render time. SECRET
// values arrive already decrypted (the resolver owns the encryptor).
type Variables map[string]Value

// Value carries a resolved variable's plaintext together with its
// declared type. The renderer uses Plaintext for substitution; Type
// + DefinedIn are kept so future destination-field validators can
// surface "this came from a SECRET" diagnostics without inspecting
// the value itself.
type Value struct {
	Type      pmv1.VariableType
	Plaintext string
	DefinedIn []string
}

// Render walks the Action proto and substitutes `{{ var.NAME }}`
// references in every templateable string field. Unresolved
// references and any leftover `{{` after substitution are returned as
// errors — the design prefers to fail loudly at dispatch time over
// silently shipping a half-rendered template to a device.
//
// deviceID is the target the variables resolve against. action is
// mutated in place; callers that need the original should clone it
// first via proto.Clone. Convenience wrapper around Resolve +
// RenderWithVars; callers rendering multiple actions for the same
// device should call those two directly to avoid re-resolving.
func (r *Renderer) Render(ctx context.Context, deviceID string, action *pmv1.Action) error {
	if action == nil {
		return nil
	}
	vars, err := r.Resolve(ctx, deviceID)
	if err != nil {
		return err
	}
	return r.RenderWithVars(ctx, action, vars)
}

// Resolve is the renderer's view onto its Resolver. Exposed so a
// handler that walks many Actions for a single device can resolve
// once and pass the result into RenderWithVars per action.
func (r *Renderer) Resolve(ctx context.Context, deviceID string) (Variables, error) {
	vars, err := r.resolver.Resolve(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("resolve variables for device %s: %w", deviceID, err)
	}
	return vars, nil
}

// RenderWithVars walks the Action proto with a caller-supplied
// variable map. Mutates action in place; nil action is a no-op.
func (r *Renderer) RenderWithVars(_ context.Context, action *pmv1.Action, vars Variables) error {
	if action == nil {
		return nil
	}
	return walkMessage(action.ProtoReflect(), vars)
}

// varRefRE matches `{{ var.NAME }}` with optional whitespace around
// the inner name. Name grammar matches the SET-time validator in
// internal/api/group_variables_validator.go.
var varRefRE = regexp.MustCompile(`\{\{\s*var\.([a-z][a-z0-9_]*)\s*\}\}`)

// HasReference reports whether s contains at least one `{{ var.NAME }}`
// reference. Callers use it to gate paths that can't render templates
// (e.g. ad-hoc one-off DispatchAction, where there is no group context
// to resolve from). Cheap — regex with a string anchor; no allocation
// when s contains no `{{` at all.
func HasReference(s string) bool {
	if !strings.Contains(s, "{{") {
		return false
	}
	return varRefRE.MatchString(s)
}

// ErrUnresolvedReference is the sentinel returned when a `{{ var.X }}`
// reference can't be matched against a variable known on the target
// device. Callers can errors.Is against this to surface a
// machine-readable diagnostic; the Render call still propagates the
// wrapped error with the offending name.
var ErrUnresolvedReference = errors.New("unresolved variable reference")

// ErrUnclosedBrace is the sentinel returned when a templateable field
// contains `{{` after the substitution pass — typically the operator
// typed `{{ var.foo }` (missing closing brace) or `{ { var.foo }}`
// (typo). Better to fail than to ship the literal `{{` to a device.
var ErrUnclosedBrace = errors.New("unresolved {{ in template after substitution")

// walkMessage descends a protoreflect.Message, calling substitute on
// every templateable string field (including repeated string fields)
// and recursing into sub-messages and oneofs.
func walkMessage(msg protoreflect.Message, vars Variables) error {
	if !msg.IsValid() {
		return nil
	}
	var walkErr error
	msg.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		if err := walkField(msg, fd, val, vars); err != nil {
			walkErr = err
			return false
		}
		return true
	})
	return walkErr
}

func walkField(msg protoreflect.Message, fd protoreflect.FieldDescriptor, val protoreflect.Value, vars Variables) error {
	switch {
	case fd.IsList():
		list := val.List()
		// Only string lists are templateable — the only repeated
		// templateable fields in the proto are []string today
		// (UserParams.ssh_authorized_keys, GroupParams.members,
		// AdminPolicyParams.users, etc.).
		if fd.Kind() == protoreflect.StringKind && isTemplateable(fd) {
			for i := 0; i < list.Len(); i++ {
				out, err := substitute(list.Get(i).String(), vars)
				if err != nil {
					return fmt.Errorf("field %s[%d]: %w", fd.Name(), i, err)
				}
				list.Set(i, protoreflect.ValueOfString(out))
			}
			return nil
		}
		// Repeated message field: recurse into each element.
		if fd.Kind() == protoreflect.MessageKind {
			for i := 0; i < list.Len(); i++ {
				if err := walkMessage(list.Get(i).Message(), vars); err != nil {
					return err
				}
			}
		}
		return nil
	case fd.IsMap():
		// Maps are not currently annotated templateable (the only
		// map<string, string> field in the proto is
		// ShellParams.environment, which is intentionally NOT
		// templateable — operators set env via the string value
		// directly). No walk needed.
		return nil
	case fd.Kind() == protoreflect.MessageKind:
		return walkMessage(val.Message(), vars)
	case fd.Kind() == protoreflect.StringKind && isTemplateable(fd):
		out, err := substitute(val.String(), vars)
		if err != nil {
			return fmt.Errorf("field %s: %w", fd.Name(), err)
		}
		msg.Set(fd, protoreflect.ValueOfString(out))
		return nil
	}
	return nil
}

// isTemplateable returns true when the field carries the
// `(templateable) = true` option from sdk/proto/pm/v1/actions.proto.
// The extension is loaded via proto.GetExtension; missing options
// (the common case) yield false.
func isTemplateable(fd protoreflect.FieldDescriptor) bool {
	opts := fd.Options()
	if opts == nil {
		return false
	}
	v := proto.GetExtension(opts, pmv1.E_Templateable)
	b, ok := v.(bool)
	return ok && b
}

// substitute replaces every `{{ var.NAME }}` reference in s with the
// matching plaintext from vars. Unknown names yield ErrUnresolvedReference
// and any leftover `{{` after the pass yields ErrUnclosedBrace —
// both surface to the caller wrapped with field context.
func substitute(s string, vars Variables) (string, error) {
	if s == "" {
		return s, nil
	}
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	var (
		missing []string
		out     = varRefRE.ReplaceAllStringFunc(s, func(m string) string {
			matches := varRefRE.FindStringSubmatch(m)
			if len(matches) < 2 {
				return m
			}
			name := matches[1]
			v, ok := vars[name]
			if !ok {
				missing = append(missing, name)
				return m
			}
			return v.Plaintext
		})
	)
	if len(missing) > 0 {
		// Stable diagnostic — sort + dedupe so the error message
		// doesn't depend on map iteration order.
		sort.Strings(missing)
		uniq := missing[:0]
		var prev string
		for _, n := range missing {
			if n != prev {
				uniq = append(uniq, n)
			}
			prev = n
		}
		return "", fmt.Errorf("%w: %s", ErrUnresolvedReference, strings.Join(uniq, ", "))
	}
	if strings.Contains(out, "{{") {
		return "", fmt.Errorf("%w: %q", ErrUnclosedBrace, out)
	}
	return out, nil
}
