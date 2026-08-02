package sqlitetype

import (
	"database/sql/driver"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONRoundTrip(t *testing.T) {
	var value JSON
	require.NoError(t, value.Scan(`{"enabled":true}`))
	assert.JSONEq(t, `{"enabled":true}`, string(value))
	encoded, err := value.Value()
	require.NoError(t, err)
	assert.Equal(t, driver.Value(`{"enabled":true}`), encoded)
	assert.Error(t, value.Scan(`{"broken"`))
}

func TestStringListRoundTrip(t *testing.T) {
	var value StringList
	require.NoError(t, value.Scan(`["one","two"]`))
	assert.Equal(t, StringList{"one", "two"}, value)
	encoded, err := value.Value()
	require.NoError(t, err)
	assert.JSONEq(t, `["one","two"]`, encoded.(string))
	assert.Error(t, value.Scan(`[1]`))
}
