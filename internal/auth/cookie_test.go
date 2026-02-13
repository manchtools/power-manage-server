package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetTokenCookies_Secure(t *testing.T) {
	header := make(http.Header)
	tokens := &TokenPair{
		AccessToken:  "access-tok",
		RefreshToken: "refresh-tok",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
	}
	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)

	SetTokenCookies(header, tokens, refreshExpiry, true)

	cookies := header.Values("Set-Cookie")
	require.Len(t, cookies, 2)

	// Parse both cookies
	var accessCookie, refreshCookie string
	for _, c := range cookies {
		if len(c) > len("pm_access=") && c[:len("pm_access=")] == "pm_access=" {
			accessCookie = c
		}
		if len(c) > len("pm_refresh=") && c[:len("pm_refresh=")] == "pm_refresh=" {
			refreshCookie = c
		}
	}

	assert.NotEmpty(t, accessCookie)
	assert.NotEmpty(t, refreshCookie)
	assert.Contains(t, accessCookie, "HttpOnly")
	assert.Contains(t, accessCookie, "Secure")
	assert.Contains(t, accessCookie, "SameSite=None")
	assert.Contains(t, refreshCookie, "HttpOnly")
	assert.Contains(t, refreshCookie, "Secure")
}

func TestSetTokenCookies_Insecure(t *testing.T) {
	header := make(http.Header)
	tokens := &TokenPair{
		AccessToken:  "access-tok",
		RefreshToken: "refresh-tok",
		ExpiresAt:    time.Now().Add(15 * time.Minute),
	}
	refreshExpiry := time.Now().Add(7 * 24 * time.Hour)

	SetTokenCookies(header, tokens, refreshExpiry, false)

	cookies := header.Values("Set-Cookie")
	require.Len(t, cookies, 2)

	for _, c := range cookies {
		assert.Contains(t, c, "HttpOnly")
		assert.NotContains(t, c, "SameSite=None")
		assert.Contains(t, c, "SameSite=Lax")
	}
}

func TestClearTokenCookies(t *testing.T) {
	header := make(http.Header)

	ClearTokenCookies(header, true)

	cookies := header.Values("Set-Cookie")
	require.Len(t, cookies, 2)

	for _, c := range cookies {
		assert.Contains(t, c, "Max-Age=0")
	}
}

func TestCookieFromHeader(t *testing.T) {
	header := make(http.Header)
	header.Set("Cookie", "pm_access=my-token; pm_refresh=refresh-val")

	assert.Equal(t, "my-token", CookieFromHeader(header, AccessTokenCookie))
	assert.Equal(t, "refresh-val", CookieFromHeader(header, RefreshTokenCookie))
	assert.Equal(t, "", CookieFromHeader(header, "nonexistent"))
}

func TestCookieFromHeader_NoCookies(t *testing.T) {
	header := make(http.Header)
	assert.Equal(t, "", CookieFromHeader(header, AccessTokenCookie))
}

func TestIsSecureRequest_HTTPS_Localhost(t *testing.T) {
	header := make(http.Header)
	header.Set("Origin", "https://localhost:5173")
	assert.True(t, IsSecureRequest(header))
}

func TestIsSecureRequest_HTTPS_127(t *testing.T) {
	header := make(http.Header)
	header.Set("Origin", "https://127.0.0.1:5173")
	assert.True(t, IsSecureRequest(header))
}

func TestIsSecureRequest_XForwardedProto(t *testing.T) {
	header := make(http.Header)
	header.Set("X-Forwarded-Proto", "https")
	assert.True(t, IsSecureRequest(header))
}

func TestIsSecureRequest_HTTP(t *testing.T) {
	header := make(http.Header)
	header.Set("Origin", "http://localhost:5173")
	assert.False(t, IsSecureRequest(header))
}

func TestIsSecureRequest_NoHeaders(t *testing.T) {
	header := make(http.Header)
	assert.False(t, IsSecureRequest(header))
}
