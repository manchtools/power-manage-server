package api_test

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
)

// validateExemptControlRPCs lists the ControlService RPCs whose ZERO request is
// LEGITIMATELY valid — every field is optional, so validation has nothing to
// reject and the sweep below would otherwise expect a rejection that never
// comes. Most are list/read RPCs (only optional pagination/filters) or no-field
// RPCs. Membership is intentional; TestValidateExemptControlRPCsAreRealRPCs
// guards it against rot, and the sweep itself FAILS if a non-exempt RPC stops
// rejecting its zero request (a dropped validate tag).
var validateExemptControlRPCs = map[string]bool{
	"GetCurrentUser":         true,
	"ListUsers":              true,
	"ListDevices":            true,
	"ListActions":            true,
	"ListActionSets":         true,
	"ListDefinitions":        true,
	"ListDeviceGroups":       true,
	"ListUserGroups":         true,
	"ListRoles":              true,
	"ListPermissions":        true,
	"ListTokens":             true,
	"ListExecutions":         true,
	"ListCompliancePolicies": true,
	"ListIdentityProviders":  true,
	"ListAuditEvents":        true,
	"ListAssignments":        true,
	"ListAuthMethods":        true,
	"GetServerSettings":      true,
	"Search":                 true,
	"GetTOTPStatus":          true,
	"RebuildSearchIndex":     true,
	// No-required-field RPCs scoped to the current user / instance.
	"ListActiveTerminalSessions": true,
	"ListIdentityLinks":          true,
	"SetupTOTP":                  true,
	// Gateway CRL/list RPCs (spec 31): empty request messages, no validatable
	// fields. The CRL fetch is agent-facing; ListGateways is permission-gated.
	"GetCertificateRevocationList": true,
	"ListGateways":                 true,
	// UpdateServerSettings is a partial update — every field is optional.
	"UpdateServerSettings": true,
	// Validate* RPCs return the verdict in their RESPONSE; an empty query is a
	// valid REQUEST (the handler reports invalidity, it is not a request error).
	"ValidateDynamicQuery":   true,
	"ValidateUserGroupQuery": true,
}

// TestEveryControlRPCRunsValidateBeforeWork is a self-discovering boundary
// guard: for every ControlService RPC whose request carries a required/bounded
// field, sending a ZERO request through the REAL client → interceptor chain
// (logging → auth → validation → authz) with a valid admin token MUST surface
// CodeInvalidArgument — proving Validate() runs before the handler does any
// work. RPCs whose zero request is legitimately valid are exempted via
// validateExemptControlRPCs. The reflection drive constructs each request
// generically so a newly-added RPC is covered automatically.
func TestEveryControlRPCRunsValidateBeforeWork(t *testing.T) {
	f := newControlRPCFixture(t)
	ctx := context.Background()

	clientVal := reflect.ValueOf(f.client)
	ifaceType := reflect.TypeOf((*pmv1connect.ControlServiceClient)(nil)).Elem()
	require.NotZero(t, ifaceType.NumMethod(), "no ControlService RPCs discovered — sweep would pass vacuously")

	checked := 0
	for i := 0; i < ifaceType.NumMethod(); i++ {
		name := ifaceType.Method(i).Name
		t.Run(name, func(t *testing.T) {
			method := clientVal.MethodByName(name)
			// In(1) is *connect.Request[FooRequest].
			reqPtr := reflect.New(method.Type().In(1).Elem())
			// connect.Request.Msg is an exported *FooRequest — set the zero value.
			msgField := reqPtr.Elem().FieldByName("Msg")
			msgField.Set(reflect.New(msgField.Type().Elem()))
			// Attach the admin bearer so authz can never be the rejecter.
			hdr := reqPtr.MethodByName("Header").Call(nil)[0].Interface().(http.Header)
			hdr.Set("Authorization", "Bearer "+f.accessToken)

			out := method.Call([]reflect.Value{reflect.ValueOf(ctx), reqPtr})
			var err error
			if e := out[1].Interface(); e != nil {
				err = e.(error)
			}
			code := connect.CodeOf(err)

			if validateExemptControlRPCs[name] {
				assert.NotEqualf(t, connect.CodeInvalidArgument, code,
					"%s is exempt (zero request expected valid) but returned CodeInvalidArgument — remove it from validateExemptControlRPCs", name)
				return
			}
			checked++
			assert.Equalf(t, connect.CodeInvalidArgument, code,
				"%s zero request must be rejected with CodeInvalidArgument before the handler runs (got %v, err=%v) — add a validate tag, or exempt it if its zero request is legitimately valid", name, code, err)
		})
	}
	require.Positive(t, checked, "no non-exempt RPCs were validated — the exempt list swallowed everything")
}

// TestValidateExemptControlRPCsAreRealRPCs guards the exempt allowlist against
// rot: every entry must name a live ControlService RPC, so a renamed/removed RPC
// can't leave a stale exemption that silently widens the gap.
func TestValidateExemptControlRPCsAreRealRPCs(t *testing.T) {
	ifaceType := reflect.TypeOf((*pmv1connect.ControlServiceClient)(nil)).Elem()
	real := make(map[string]bool, ifaceType.NumMethod())
	for i := 0; i < ifaceType.NumMethod(); i++ {
		real[ifaceType.Method(i).Name] = true
	}
	require.NotEmpty(t, validateExemptControlRPCs)
	for name := range validateExemptControlRPCs {
		assert.Truef(t, real[name], "validateExemptControlRPCs names %q but no such ControlService RPC — stale exemption", name)
	}
}
