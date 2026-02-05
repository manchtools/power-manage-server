package auth

import (
	"net/http"
	"time"
)

const (
	AccessTokenCookie  = "pm_access"
	RefreshTokenCookie = "pm_refresh"
)

// SetTokenCookies sets httpOnly cookies for access and refresh tokens on the response headers.
// When secure is true (HTTPS via reverse proxy), SameSite=None is used to allow cross-origin
// requests from a web UI on a different domain. SameSite=None requires Secure=true.
// When secure is false (development over HTTP), SameSite=Lax is used instead since
// SameSite=None without Secure is rejected by browsers.
func SetTokenCookies(header http.Header, tokens *TokenPair, refreshExpiry time.Time, secure bool) {
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}

	accessCookie := &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		Expires:  tokens.ExpiresAt,
	}
	header.Add("Set-Cookie", accessCookie.String())

	refreshCookie := &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		Expires:  refreshExpiry,
	}
	header.Add("Set-Cookie", refreshCookie.String())
}

// ClearTokenCookies removes the token cookies by setting them to expire immediately.
func ClearTokenCookies(header http.Header, secure bool) {
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}

	for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: sameSite,
			MaxAge:   -1,
		}
		header.Add("Set-Cookie", cookie.String())
	}
}

// CookieFromHeader extracts a named cookie value from HTTP request headers.
func CookieFromHeader(header http.Header, name string) string {
	r := &http.Request{Header: header}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// IsSecureRequest checks whether the request was made over HTTPS.
func IsSecureRequest(header http.Header) bool {
	return header.Get("X-Forwarded-Proto") == "https"
}
