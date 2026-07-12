package api_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/api"
	"github.com/manchtools/power-manage/server/internal/testutil"
)

// TestBatchIDFields_CappedAt256 pins spec 29 S7: the repeated batch ID request
// fields carry max=256 (via the SDK @gotags validate tag) so one request can't
// drive unbounded O(N) work. api.Validate runs the same go-playground validator
// every ControlService handler invokes (TestEveryControlRPCRunsValidateBeforeWork
// proves that), so rejection here is rejection at the real boundary.
//
// Each case builds an OTHERWISE-VALID request and varies only the capped field:
// 256 passes, 257 is rejected — isolating the count cap as the cause. All eight
// capped request fields are covered, so a cap accidentally dropped from any one
// in a future SDK regen is caught here.
func TestBatchIDFields_CappedAt256(t *testing.T) {
	ulids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = testutil.NewID()
		}
		return out
	}
	valid := testutil.NewID()

	// All eight capped request fields, each built otherwise-valid (required
	// anchors set to a valid ULID) so only the batch length varies.
	cases := []struct {
		name  string
		build func(ids []string) any
	}{
		{"DispatchToMultipleRequest.device_ids", func(ids []string) any {
			return &pm.DispatchToMultipleRequest{
				DeviceIds:    ids,
				ActionSource: &pm.DispatchToMultipleRequest_ActionId{ActionId: valid},
			}
		}},
		{"CreateUserRequest.role_ids", func(ids []string) any {
			return &pm.CreateUserRequest{Email: "user@test.com", Password: "password123", RoleIds: ids}
		}},
		{"AssignDeviceRequest.user_ids", func(ids []string) any {
			return &pm.AssignDeviceRequest{DeviceId: valid, UserIds: ids}
		}},
		{"AssignDeviceRequest.group_ids", func(ids []string) any {
			return &pm.AssignDeviceRequest{DeviceId: valid, GroupIds: ids}
		}},
		{"AddDeviceToGroupRequest.device_ids", func(ids []string) any {
			return &pm.AddDeviceToGroupRequest{GroupId: valid, DeviceIds: ids}
		}},
		{"AssignRoleToUserRequest.role_ids", func(ids []string) any {
			return &pm.AssignRoleToUserRequest{UserId: valid, RoleIds: ids}
		}},
		{"AddUserToGroupRequest.user_ids", func(ids []string) any {
			return &pm.AddUserToGroupRequest{GroupId: valid, UserIds: ids}
		}},
		{"AssignRoleToUserGroupRequest.role_ids", func(ids []string) any {
			return &pm.AssignRoleToUserGroupRequest{GroupId: valid, RoleIds: ids}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, api.Validate(context.Background(), tc.build(ulids(256))),
				"a batch at the 256 cap must pass validation")

			err := api.Validate(context.Background(), tc.build(ulids(257)))
			require.Error(t, err, "a batch of 257 ids must be rejected by max=256")
			assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		})
	}
}
