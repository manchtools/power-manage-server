package config

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateControlURL validates a gateway control (InternalService) URL at
// startup and returns its non-secret origin — scheme://host[:port] — for
// logging (spec 29 AC8-9).
//
// The accepted shape is HTTPS with a non-empty host and no user-info, query,
// or fragment: an InternalService base URL never legitimately carries any of
// those, and each is a channel through which a credential could be smuggled
// into startup logs. A path is permitted (Connect base URLs may have one) but
// is stripped from the returned origin.
//
// On rejection the error names the offending component but never echoes the
// raw URL, so a mistyped or injected credential-bearing value is not leaked to
// logs. The origin is empty on error.
func ValidateControlURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("control URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("control URL is malformed")
	}
	if u.Scheme != "https" {
		return "", errors.New("control URL must use the https scheme")
	}
	// u.Host is host[:port]; Hostname() strips the port. A space or other stray
	// character in the authority means a malformed URL that url.Parse tolerated.
	if u.Host == "" || u.Hostname() == "" {
		return "", errors.New("control URL has no host")
	}
	if strings.ContainsAny(u.Host, " \t") {
		return "", errors.New("control URL host is malformed")
	}
	if u.User != nil {
		return "", errors.New("control URL must not contain user-info credentials")
	}
	if u.RawQuery != "" {
		return "", errors.New("control URL must not contain a query string")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", errors.New("control URL must not contain a fragment")
	}
	return u.Scheme + "://" + u.Host, nil
}
