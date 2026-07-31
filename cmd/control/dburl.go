package main

import urlpkg "net/url"

// maskDatabaseURL replaces the password in a connection string so it
// can be logged.
//
// Parsed with net/url rather than scanned by hand: a password may
// legitimately contain ':' or '@' in percent-encoded form, and a
// hand-rolled scan mangles exactly those cases — which is how a
// credential ends up in a log line that was meant to hide it.
func maskDatabaseURL(raw string) string {
	u, err := urlpkg.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return raw
	}
	u.User = urlpkg.UserPassword(u.User.Username(), "***")
	return u.String()
}
