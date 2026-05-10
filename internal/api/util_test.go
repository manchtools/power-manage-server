package api

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// TestParsePageToken_Validity locks the parser contract: numeric
// tokens parse to int64, non-numeric tokens return an error. The
// caller (parsePagination in helpers.go) treats the error as
// "invalid page token" and surfaces a 400 — these tests pin the
// boundary between "ok" and "let helpers turn it into a 400".
func TestParsePageToken_Validity(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{name: "zero", in: "0", want: 0},
		{name: "positive", in: "42", want: 42},
		{name: "large", in: "9223372036854775807", want: 9223372036854775807},
		{name: "empty", in: "", wantErr: true},
		{name: "non-numeric", in: "abc", wantErr: true},
		{name: "trailing-junk", in: "10x", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePageToken(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestFormatPageToken_RoundTrip locks the format ↔ parse symmetry:
// every int64 the offset getter could produce must round-trip.
func TestFormatPageToken_RoundTrip(t *testing.T) {
	for _, in := range []int64{0, 1, 50, 100, 1_000_000} {
		t.Run(strconv.FormatInt(in, 10), func(t *testing.T) {
			out := formatPageToken(in)
			parsed, err := parsePageToken(out)
			require.NoError(t, err)
			assert.Equal(t, in, parsed)
		})
	}
}

// TestNewULID_NonEmpty just checks the helper produces unique
// non-empty strings — `ulid.Make` is the underlying implementation,
// so this is a smoke test rather than an exhaustive ULID property test.
func TestNewULID_NonEmpty(t *testing.T) {
	a := newULID()
	b := newULID()
	assert.NotEmpty(t, a)
	assert.NotEmpty(t, b)
	assert.NotEqual(t, a, b, "successive newULID calls must differ")
}

// TestUserFilterID_Unrestricted asserts that a context whose user
// holds the unscoped permission produces nil — the SQL query filters
// nothing.
func TestUserFilterID_Unrestricted(t *testing.T) {
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          "user-1",
		Permissions: []string{"ListDevices"},
	})
	assert.Nil(t, userFilterID(ctx, "ListDevices"))
}

// TestUserFilterID_Scoped asserts that a context whose user lacks
// the unscoped permission gets their own ID returned for SQL-level
// filtering.
func TestUserFilterID_Scoped(t *testing.T) {
	ctx := auth.WithUser(context.Background(), &auth.UserContext{
		ID:          "user-2",
		Permissions: []string{"ListDevices:assigned"},
	})
	got := userFilterID(ctx, "ListDevices")
	require.NotNil(t, got)
	assert.Equal(t, "user-2", *got)
}

// TestUserFilterID_NoUser is the defensive path: missing user
// context returns nil so the caller's downstream nil-check applies.
func TestUserFilterID_NoUser(t *testing.T) {
	assert.Nil(t, userFilterID(context.Background(), "ListDevices"))
}
