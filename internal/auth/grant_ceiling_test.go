package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUncoveredPermissions encodes the "grant only what you hold" contract,
// including the broader-implies-narrower scope rule and the admin-covers-all
// invariant (#365).
func TestUncoveredPermissions(t *testing.T) {
	cases := []struct {
		name    string
		held    []string
		granted []string
		want    []string
	}{
		{
			name:    "exact subset is fully covered",
			held:    []string{"CreateUser", "ListUsers", "DeleteUser"},
			granted: []string{"CreateUser", "ListUsers"},
			want:    nil,
		},
		{
			name:    "granting a permission not held is uncovered",
			held:    []string{"CreateUser"},
			granted: []string{"CreateUser", "DispatchAction"},
			want:    []string{"DispatchAction"},
		},
		{
			name:    "holding unrestricted covers granting the :self scope",
			held:    []string{"GetUser"},
			granted: []string{"GetUser:self"},
			want:    nil,
		},
		{
			name:    "holding unrestricted covers granting the :assigned scope",
			held:    []string{"GetDevice"},
			granted: []string{"GetDevice:assigned"},
			want:    nil,
		},
		{
			name:    "holding only :self does NOT cover granting the unrestricted form",
			held:    []string{"GetUser:self"},
			granted: []string{"GetUser"},
			want:    []string{"GetUser"},
		},
		{
			name:    "holding :self covers granting the same :self",
			held:    []string{"GetUser:self"},
			granted: []string{"GetUser:self"},
			want:    nil,
		},
		{
			name:    "admin holding all permissions covers any grant",
			held:    AdminPermissions(),
			granted: []string{"DispatchAction", "DeleteDevice", "GetUser:self", "GetDevice:assigned"},
			want:    nil,
		},
		{
			name:    "empty grant is always covered",
			held:    []string{"CreateUser"},
			granted: nil,
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, UncoveredPermissions(tc.held, tc.granted))
		})
	}
}
