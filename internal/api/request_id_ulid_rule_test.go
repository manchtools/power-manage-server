package api_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/gen/go/pm/v1/pmv1connect"
)

// idRuleExemptFields lists string request fields whose name ends in "Id" but
// which are NOT ULIDs (so a `ulid` validate rule would be wrong). Calibrated by
// running TestRequestIDFieldsCarryULIDRule and classifying what it surfaces;
// each entry is "MessageType.FieldName". Guarded against rot below.
var idRuleExemptFields = map[string]bool{
	// OIDC client_id: a provider-issued identifier string (e.g.
	// "…apps.googleusercontent.com"), not a ULID.
	"CreateIdentityProviderRequest.ClientId": true,
	"UpdateIdentityProviderRequest.ClientId": true,
	// Audit actor filter: an actor may be a user (ULID) OR a non-ULID system /
	// device actor, so the filter accepts any non-empty string.
	"ListAuditEventsRequest.ActorId": true,
	// Gateway identifier: an operator/registry-assigned gateway id (bounded
	// string, not a ULID — see the device→gateway registry / WS2).
	"VerifyDeviceRequest.GatewayId":              true,
	"InternalSyncActionsRequest.GatewayId":       true,
	"InternalValidateLuksTokenRequest.GatewayId": true,
	"InternalGetLuksKeyRequest.GatewayId":        true,
	"InternalStoreLuksKeyRequest.GatewayId":      true,
	"InternalStoreLpsPasswordsRequest.GatewayId": true,
}

// TestRequestIDFieldsCarryULIDRule pins WS17b f4's intent-derived-rule depth:
// it is not enough that a request id field carries SOME validate tag (the
// boundary sweep proves a zero request is rejected) — an id field mistagged
// e.g. `validate:"max=1"` instead of a ULID rule would still reject the zero
// request yet accept a non-ULID value. So: every string request field whose name
// ends in "Id" must carry a `ulid` rule in its validate tag, unless explicitly
// exempted as a non-ULID identifier.
func TestRequestIDFieldsCarryULIDRule(t *testing.T) {
	ifaces := []reflect.Type{
		reflect.TypeOf((*pmv1connect.ControlServiceClient)(nil)).Elem(),
		reflect.TypeOf((*pmv1connect.InternalServiceHandler)(nil)).Elem(),
	}
	seen := map[reflect.Type]bool{}
	idFields := 0
	usedExempt := map[string]bool{}

	for _, iface := range ifaces {
		for i := 0; i < iface.NumMethod(); i++ {
			reqArg := iface.Method(i).Type.In(1) // *connect.Request[T]
			if reqArg.Kind() != reflect.Ptr {
				continue
			}
			msgField, ok := reqArg.Elem().FieldByName("Msg")
			if !ok {
				continue
			}
			msgType := msgField.Type.Elem() // the request message struct T
			if seen[msgType] {
				continue
			}
			seen[msgType] = true
			for f := 0; f < msgType.NumField(); f++ {
				field := msgType.Field(f)
				if field.Type.Kind() != reflect.String || !strings.HasSuffix(field.Name, "Id") {
					continue
				}
				idFields++
				key := msgType.Name() + "." + field.Name
				if idRuleExemptFields[key] {
					usedExempt[key] = true
					continue
				}
				tag := field.Tag.Get("validate")
				assert.Containsf(t, tag, "ulid",
					"%s is an *Id string field but its validate tag %q has no ulid rule — a non-ULID value would be accepted. Add a ulid rule, or exempt it in idRuleExemptFields if it is not a ULID.", key, tag)
			}
		}
	}
	require.Positive(t, idFields, "matches-zero guard: discovered no *Id string request fields — the reflection walk is dead")
	for key := range idRuleExemptFields {
		assert.Truef(t, usedExempt[key], "stale idRuleExemptFields entry %q matched no request field", key)
	}
}
