package api

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/auth"
)

// TestRequireAuth_Success returns the embedded user context unchanged.
func TestRequireAuth_Success(t *testing.T) {
	want := &auth.UserContext{ID: "user-1", Email: "alice@example.com"}
	ctx := auth.WithUser(context.Background(), want)
	got, err := requireAuth(ctx)
	require.NoError(t, err)
	assert.Same(t, want, got)
}

// TestRequireAuth_NoUser returns the standardized
// CodeUnauthenticated error so handlers can return it straight
// through without per-RPC error wrapping.
func TestRequireAuth_NoUser(t *testing.T) {
	_, err := requireAuth(context.Background())
	require.Error(t, err)
	cerr := new(connect.Error)
	require.True(t, errors.As(err, &cerr))
	assert.Equal(t, connect.CodeUnauthenticated, cerr.Code())
}

// TestHandleGetError_NotFound maps pgx.ErrNoRows to the supplied
// not-found code with CodeNotFound. Any other error collapses to
// CodeInternal so a database hiccup never leaks "row not found"
// to the client when the row actually exists but the read failed.
func TestHandleGetError_NotFound(t *testing.T) {
	err := handleGetError(context.Background(), pgx.ErrNoRows, ErrUserNotFound, "user not found")
	require.Error(t, err)
	cerr := new(connect.Error)
	require.True(t, errors.As(err, &cerr))
	assert.Equal(t, connect.CodeNotFound, cerr.Code())
}

func TestHandleGetError_Other(t *testing.T) {
	err := handleGetError(context.Background(), errors.New("connection refused"), ErrUserNotFound, "user not found")
	require.Error(t, err)
	cerr := new(connect.Error)
	require.True(t, errors.As(err, &cerr))
	assert.Equal(t, connect.CodeInternal, cerr.Code())
}

// TestParsePagination_Defaults locks the bounds: zero / negative
// pageSize means "use 50", > 100 clamps to 100, missing pageToken
// means offset 0.
func TestParsePagination_Defaults(t *testing.T) {
	cases := []struct {
		name   string
		size   int32
		token  string
		want   int32
		offset int32
	}{
		{name: "zero defaults to 50", size: 0, want: 50},
		{name: "negative defaults to 50", size: -1, want: 50},
		{name: "in-range", size: 25, want: 25},
		{name: "above-max clamps", size: 999, want: 100},
		{name: "valid token", size: 50, token: "100", want: 50, offset: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			size, off, err := parsePagination(tc.size, tc.token)
			require.NoError(t, err)
			assert.Equal(t, tc.want, size)
			assert.Equal(t, tc.offset, off)
		})
	}
}

// TestParsePagination_BadToken returns CodeInvalidArgument with
// ErrInvalidPageToken so the client knows to stop paginating.
func TestParsePagination_BadToken(t *testing.T) {
	cases := []string{"abc", "-1", "999999999999999999999"}
	for _, tok := range cases {
		t.Run(tok, func(t *testing.T) {
			_, _, err := parsePagination(50, tok)
			require.Error(t, err)
			cerr := new(connect.Error)
			require.True(t, errors.As(err, &cerr))
			assert.Equal(t, connect.CodeInvalidArgument, cerr.Code())
		})
	}
}

// TestBuildNextPageToken_HasMore emits the next offset only when
// the result is full AND there are more rows after it. Either
// short result OR end-of-data returns empty.
func TestBuildNextPageToken_HasMore(t *testing.T) {
	cases := []struct {
		name        string
		resultCount int32
		offset      int32
		pageSize    int32
		total       int64
		want        string
	}{
		{name: "exactly-page-size, more remain", resultCount: 50, offset: 0, pageSize: 50, total: 200, want: "50"},
		{name: "exactly-page-size, last page", resultCount: 50, offset: 150, pageSize: 50, total: 200, want: ""},
		{name: "short result", resultCount: 10, offset: 0, pageSize: 50, total: 200, want: ""},
		{name: "first of two", resultCount: 50, offset: 0, pageSize: 50, total: 60, want: "50"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNextPageToken(tc.resultCount, tc.offset, tc.pageSize, tc.total)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestPtrBool_PtrStr lock the omitempty-pointer-helpers. They're
// trivial but the typed-payload emit sites depend on them being
// "always non-nil" so projector "preserve vs explicit-set"
// semantics work.
func TestPtrBool_PtrStr(t *testing.T) {
	bp := ptrBool(true)
	require.NotNil(t, bp)
	assert.True(t, *bp)
	bp2 := ptrBool(false)
	require.NotNil(t, bp2)
	assert.False(t, *bp2)

	sp := ptrStr("hello")
	require.NotNil(t, sp)
	assert.Equal(t, "hello", *sp)
	sp2 := ptrStr("")
	require.NotNil(t, sp2)
	assert.Equal(t, "", *sp2)
}
