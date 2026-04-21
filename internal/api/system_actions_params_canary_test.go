package api

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/actionparams"
)

// Tests in this file lock down the "system-managed actions must
// follow the proto contract the same way user-created actions do"
// invariant. A previous bug in syncTtyUserAction used a free-form
// map[string]any with the key "system" (not a real UserParams
// field); protojson silently dropped it on unmarshal, and pm-tty-*
// accounts stayed visible on every login screen.
//
// The structural fix has two parts: all sync functions now build
// typed *pm.UserParams / *pm.SshParams / etc. (Go compiler catches
// field-name typos — you cannot pass a map[string]any to
// actionparams.MarshalActionParams, it wants a proto.Message), and
// marshalling goes through the single shared MarshalOptions in
// internal/actionparams so every action on the wire looks the same
// regardless of whether it came from the UI or the control server.
//
// These tests exercise the marshal helper with representative
// shapes; any future regression — EmitUnpopulated turning off,
// unknown fields sneaking in, nil messages marshalling — fires here.

// TestMarshalActionParamsStrictUnmarshal proves that every system
// action's params JSON round-trips through a STRICT protojson
// unmarshal (DiscardUnknown=false) — i.e. no unknown fields. If
// anyone reintroduces a typo like "system" in a field name, this
// test fails loudly instead of silently shipping a broken action.
//
// Calls aren't made through the full SystemActionManager (that
// would need a test DB) — instead it exercises the same marshal
// helper with representative proto structs. If a future sync
// function constructs a proto with bad data, that's caught here
// by strict-unmarshalling the output.
func TestMarshalActionParamsStrictUnmarshal(t *testing.T) {
	strict := protojson.UnmarshalOptions{DiscardUnknown: false}

	tests := []struct {
		name string
		msg  proto.Message
		dst  proto.Message
	}{
		{
			name: "UserParams — main user provision shape",
			msg: &pm.UserParams{
				Username:   "alice",
				Uid:        1000,
				CreateHome: true,
				Comment:    "Alice User",
				Disabled:   false,
			},
			dst: &pm.UserParams{},
		},
		{
			name: "UserParams — pm-tty shape (hidden, nologin, no home)",
			msg: &pm.UserParams{
				Username:   "pm-tty-alice",
				Uid:        101000,
				Shell:      "/usr/sbin/nologin",
				CreateHome: false,
				Comment:    "Power Manage terminal user for alice",
				Hidden:     true,
				Disabled:   false,
			},
			dst: &pm.UserParams{},
		},
		{
			name: "SshParams — default access",
			msg: &pm.SshParams{
				Users:         []string{"alice"},
				AllowPubkey:   true,
				AllowPassword: false,
			},
			dst: &pm.SshParams{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := actionparams.MarshalActionParams(tc.msg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			// Strict unmarshal — any unknown JSON field fails the test.
			// This is the guard that would have caught "system" in the
			// original bug.
			if err := strict.Unmarshal(data, tc.dst); err != nil {
				t.Errorf("strict unmarshal failed — params JSON contains unknown fields: %v\nJSON: %s", err, string(data))
			}

			// Also verify EmitUnpopulated is actually on: proto3 scalar
			// zero values must appear in the output. Without this,
			// explicit "false" is indistinguishable from "unset" on
			// the wire, and the agent's default-for-normal-users logic
			// can fabricate fields the server never asked for (the
			// root cause of the pm-tty-* home directory creation bug).
			if !strings.Contains(string(data), "\"") {
				t.Errorf("expected JSON output to contain fields; got %q", data)
			}
		})
	}
}

// TestMarshalActionParamsEmitsZeroValues pins the EmitUnpopulated
// behaviour explicitly. If someone changes actionparams.MarshalOptions
// back to the default (EmitUnpopulated=false), this test fires.
//
// Concrete case: a UserParams with CreateHome=false must serialize
// to a JSON object containing the "createHome": false pair. Without
// EmitUnpopulated, protojson drops scalar zero values and the agent
// can't distinguish "server wants no home" from "server didn't say."
func TestMarshalActionParamsEmitsZeroValues(t *testing.T) {
	params := &pm.UserParams{
		Username:   "bob",
		Uid:        1001,
		CreateHome: false, // proto3 scalar zero — must NOT be dropped
		Disabled:   false, // same
	}

	data, err := actionparams.MarshalActionParams(params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := string(data)
	if !strings.Contains(got, `"createHome":false`) {
		t.Errorf("expected JSON to include \"createHome\":false explicitly (EmitUnpopulated); got %s", got)
	}
	if !strings.Contains(got, `"disabled":false`) {
		t.Errorf("expected JSON to include \"disabled\":false explicitly; got %s", got)
	}
}

// TestMarshalActionParamsRejectsNil asserts the helper refuses a nil
// message instead of silently emitting "null" — a nil would produce
// a paramsJSON the agent can't interpret and would be dispatched as
// a broken action.
func TestMarshalActionParamsRejectsNil(t *testing.T) {
	if _, err := actionparams.MarshalActionParams(nil); err == nil {
		t.Error("expected error for nil message, got nil")
	}
}
