package template

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pmv1 "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// staticResolver is a tiny test double that returns a pre-built map.
// Tests use it instead of the production StoreResolver so they don't
// need a Postgres / projection round-trip.
type staticResolver struct {
	vars Variables
	err  error
}

func (s staticResolver) Resolve(_ context.Context, _ string) (Variables, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.vars, nil
}

func newRendererFor(vars Variables) *Renderer {
	return New(staticResolver{vars: vars})
}

func TestRender_HappyPath_TemplateableStringField(t *testing.T) {
	r := newRendererFor(Variables{
		"pkg": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "nginx"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_PACKAGE,
		Params: &pmv1.Action_Package{
			Package: &pmv1.PackageParams{Name: "{{ var.pkg }}"},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	assert.Equal(t, "nginx", action.GetPackage().GetName())
}

func TestRender_UnknownVariable_ReturnsErrUnresolvedReference(t *testing.T) {
	r := newRendererFor(Variables{})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_PACKAGE,
		Params: &pmv1.Action_Package{
			Package: &pmv1.PackageParams{Name: "{{ var.missing }}"},
		},
	}
	err := r.Render(context.Background(), "dev", action)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnresolvedReference), "want ErrUnresolvedReference, got %v", err)
	assert.Contains(t, err.Error(), "missing")
}

func TestRender_UnclosedBrace_ReturnsErrUnclosedBrace(t *testing.T) {
	r := newRendererFor(Variables{
		"pkg": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "nginx"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_PACKAGE,
		Params: &pmv1.Action_Package{
			// Trailing `{{` after the substitution pass — typo on the
			// operator's part, must fail rather than ship literally.
			Package: &pmv1.PackageParams{Name: "{{ var.pkg }}-{{x"},
		},
	}
	err := r.Render(context.Background(), "dev", action)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnclosedBrace), "want ErrUnclosedBrace, got %v", err)
}

func TestRender_NonTemplateableMapField_LeftAlone(t *testing.T) {
	// ShellParams.environment is a map<string,string> intentionally
	// NOT marked templateable. The walker must NOT touch it even when
	// the value contains `{{ var.foo }}`.
	r := newRendererFor(Variables{
		"foo": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "REPLACED"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: &pmv1.Action_Shell{
			Shell: &pmv1.ShellParams{
				Script:      "echo {{ var.foo }}",
				Environment: map[string]string{"LITERAL": "{{ var.foo }}"},
			},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	assert.Equal(t, "echo REPLACED", action.GetShell().GetScript())
	assert.Equal(t, "{{ var.foo }}", action.GetShell().GetEnvironment()["LITERAL"])
}

func TestRender_RepeatedStringField(t *testing.T) {
	// UserParams.ssh_authorized_keys is a repeated string field
	// marked templateable. Each entry must be substituted independently.
	r := newRendererFor(Variables{
		"key1": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "ssh-ed25519 AAA1"},
		"key2": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "ssh-ed25519 AAA2"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_USER,
		Params: &pmv1.Action_User{
			User: &pmv1.UserParams{
				Username: "alice",
				SshAuthorizedKeys: []string{
					"{{ var.key1 }}",
					"{{ var.key2 }}",
				},
			},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	got := action.GetUser().GetSshAuthorizedKeys()
	require.Len(t, got, 2)
	assert.Equal(t, "ssh-ed25519 AAA1", got[0])
	assert.Equal(t, "ssh-ed25519 AAA2", got[1])
}

func TestRender_NoTemplateInValue_FastPath(t *testing.T) {
	r := newRendererFor(Variables{})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_PACKAGE,
		Params: &pmv1.Action_Package{
			Package: &pmv1.PackageParams{Name: "nginx"},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	assert.Equal(t, "nginx", action.GetPackage().GetName())
}

func TestRender_NilAction_NoOp(t *testing.T) {
	r := newRendererFor(Variables{})
	require.NoError(t, r.Render(context.Background(), "dev", nil))
}

func TestRender_ResolverError_Propagates(t *testing.T) {
	r := New(staticResolver{err: errors.New("resolver boom")})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_PACKAGE,
		Params: &pmv1.Action_Package{
			Package: &pmv1.PackageParams{Name: "nginx"},
		},
	}
	err := r.Render(context.Background(), "dev", action)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolver boom")
}

func TestRender_MultipleReferencesSameField(t *testing.T) {
	r := newRendererFor(Variables{
		"a": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "first"},
		"b": {Type: pmv1.VariableType_VARIABLE_TYPE_STRING, Plaintext: "second"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: &pmv1.Action_Shell{
			Shell: &pmv1.ShellParams{Script: "{{ var.a }} and {{ var.b }} and {{var.a}}"},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	assert.Equal(t, "first and second and first", action.GetShell().GetScript())
}

func TestRender_MultipleUnresolved_SortedAndDeduped(t *testing.T) {
	// Two distinct missing names + a duplicate of one of them; the
	// error message must list each name once, sorted, so operators
	// see a stable diagnostic.
	r := newRendererFor(Variables{})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_SHELL,
		Params: &pmv1.Action_Shell{
			Shell: &pmv1.ShellParams{Script: "{{ var.zeta }} {{ var.alpha }} {{ var.zeta }}"},
		},
	}
	err := r.Render(context.Background(), "dev", action)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnresolvedReference))
	assert.Contains(t, err.Error(), "alpha, zeta")
}

func TestRender_SecretValue_SubstitutesPlaintext(t *testing.T) {
	// SECRET-typed values arrive at the renderer already decrypted.
	// The renderer doesn't care about the type — it substitutes the
	// plaintext like any other value. Documented here so future
	// changes don't accidentally start treating SECRET differently.
	r := newRendererFor(Variables{
		"db_password": {Type: pmv1.VariableType_VARIABLE_TYPE_SECRET, Plaintext: "hunter2"},
	})
	action := &pmv1.Action{
		Id:   &pmv1.ActionId{Value: "01HX0000000000000000000000"},
		Type: pmv1.ActionType_ACTION_TYPE_FILE,
		Params: &pmv1.Action_File{
			File: &pmv1.FileParams{
				Path:    "/etc/myapp.conf",
				Content: "password={{ var.db_password }}",
			},
		},
	}
	require.NoError(t, r.Render(context.Background(), "dev", action))
	assert.Equal(t, "password=hunter2", action.GetFile().GetContent())
}
