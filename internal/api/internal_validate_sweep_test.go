package api_test

import (
	"context"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// validateExemptInternalRPCs lists InternalService RPCs whose ZERO request is
// legitimately valid (every field optional). Empty today: every InternalService
// request carries a required device_id / token / session_id. The no-stale guard
// below keeps this from rotting open.
var validateExemptInternalRPCs = map[string]bool{}

// TestEveryInternalRPCRunsValidateBeforeWork is the InternalService counterpart
// to TestEveryControlRPCRunsValidateBeforeWork (WS17b f8): for every
// InternalService RPC, calling the REAL handler with a ZERO request must surface
// CodeInvalidArgument — proving validation runs BEFORE the handler does any work
// (including before the gateway-binding/authorization check, which would
// otherwise return PermissionDenied). The reflection drive covers a newly-added
// RPC automatically, so a credential-bearing endpoint that forgets to validate
// fails here.
func TestEveryInternalRPCRunsValidateBeforeWork(t *testing.T) {
	st := testutil.SetupPostgres(t)
	device := testutil.CreateTestDevice(t, st, "validate-sweep-host")
	h, _ := wiredHandler(t, st, device, "gw-A")
	ctx := context.Background()

	hVal := reflect.ValueOf(h)
	ifaceType := reflect.TypeOf((*pmv1connect.InternalServiceHandler)(nil)).Elem()
	require.NotZero(t, ifaceType.NumMethod(), "no InternalService RPCs discovered — sweep would pass vacuously")

	checked := 0
	for i := 0; i < ifaceType.NumMethod(); i++ {
		name := ifaceType.Method(i).Name
		t.Run(name, func(t *testing.T) {
			method := hVal.MethodByName(name)
			require.Truef(t, method.IsValid(), "InternalHandler is missing method %s", name)
			// In(1) is *connect.Request[FooRequest] on the bound method; build a
			// zero request with a zero Msg.
			reqPtr := reflect.New(method.Type().In(1).Elem())
			msgField := reqPtr.Elem().FieldByName("Msg")
			msgField.Set(reflect.New(msgField.Type().Elem()))

			out := method.Call([]reflect.Value{reflect.ValueOf(ctx), reqPtr})
			var err error
			if e := out[1].Interface(); e != nil {
				err = e.(error)
			}
			code := connect.CodeOf(err)

			if validateExemptInternalRPCs[name] {
				assert.NotEqualf(t, connect.CodeInvalidArgument, code,
					"%s is exempt (zero request expected valid) but returned CodeInvalidArgument — remove it from validateExemptInternalRPCs", name)
				return
			}
			checked++
			assert.Equalf(t, connect.CodeInvalidArgument, code,
				"%s zero request must be rejected with CodeInvalidArgument before the handler does work (got %v, err=%v) — validate first, or exempt it if its zero request is legitimately valid", name, code, err)
		})
	}
	require.Positive(t, checked, "no non-exempt InternalService RPCs were validated — the exempt list swallowed everything")
}

// TestValidateExemptInternalRPCsAreRealRPCs guards the exempt allowlist against
// rot: every entry must name a live InternalService RPC.
func TestValidateExemptInternalRPCsAreRealRPCs(t *testing.T) {
	ifaceType := reflect.TypeOf((*pmv1connect.InternalServiceHandler)(nil)).Elem()
	realRPCs := make(map[string]bool, ifaceType.NumMethod())
	for i := 0; i < ifaceType.NumMethod(); i++ {
		realRPCs[ifaceType.Method(i).Name] = true
	}
	for name := range validateExemptInternalRPCs {
		assert.Truef(t, realRPCs[name], "validateExemptInternalRPCs names %q but no such InternalService RPC — stale exemption", name)
	}
}
