// Package datastore validates the control server's PostgreSQL transport
// posture. PostgreSQL is the only external datastore in the target runtime.
package datastore

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// RequirePostgresTLS returns an error unless connString is configured for mutual
// TLS: sslmode=verify-full with the client-cert material (sslrootcert/sslcert/
// sslkey) present. A sslmode=disable or absent DSN, or verify-full without the
// cert params, is a boot-time fail-closed error; the target permits no plaintext
// downgrade. pgx passes these libpq params through natively, so this validates
// posture rather than rewriting the DSN.
func RequirePostgresTLS(connString string) error {
	params, err := dsnParams(connString)
	if err != nil {
		return errors.New("datastore: invalid PostgreSQL DSN")
	}
	if got := params["sslmode"]; got != "verify-full" {
		return fmt.Errorf("datastore: Postgres sslmode=%q; verify-full mutual TLS is required", got)
	}
	for _, k := range []string{"sslrootcert", "sslcert", "sslkey"} {
		if params[k] == "" {
			return fmt.Errorf("datastore: Postgres DSN missing %s (client-cert material is required for verify-full)", k)
		}
	}
	return nil
}

// dsnParams extracts the parameter map from either DSN form pgx accepts: the
// URL form (postgres://user:pass@host/db?sslmode=…) or the keyword form
// (host=… sslmode=…). Only the parameters are needed; credentials in the URL
// userinfo are ignored (and never returned).
func dsnParams(connString string) (map[string]string, error) {
	out := map[string]string{}
	// libpq recognizes a URI by exactly these two scheme prefixes; anything else
	// is keyword/value form. A substring "://" check would mis-route a keyword
	// DSN whose quoted value contains a URL (e.g. password='https://…') through
	// URL parsing and destroy its real parameters.
	if strings.HasPrefix(connString, "postgres://") || strings.HasPrefix(connString, "postgresql://") {
		u, err := url.Parse(connString)
		if err != nil {
			return nil, fmt.Errorf("datastore: parse DSN: %w", err)
		}
		for k, v := range u.Query() {
			if len(v) > 0 {
				out[k] = v[len(v)-1]
			}
		}
		return out, nil
	}
	// Keyword/value form. Tokenize with libpq's single-quote + backslash-escape
	// rules rather than a bare whitespace split: a quoted value containing spaces
	// (e.g. application_name='my app') must stay one token. Otherwise a crafted
	// value like application_name='x sslmode=verify-full' would split into a
	// spurious `sslmode=verify-full` token that overwrites the real sslmode and
	// tricks RequirePostgresTLS into accepting a plaintext DSN — defeating the
	// fail-closed guarantee this file exists to provide.
	toks, err := splitKeywordDSN(connString)
	if err != nil {
		return nil, err
	}
	for _, kv := range toks {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[strings.TrimSpace(kv[:i])] = kv[i+1:]
		}
	}
	return out, nil
}

// splitKeywordDSN tokenizes a libpq keyword/value connection string, honoring
// single-quote quoting and backslash escapes (per libpq's documented rules) so
// whitespace inside a quoted value does not split it. Quote characters are
// consumed (not emitted); a backslash escapes the next character literally.
// An unterminated quote or trailing escape is an error, as in libpq — a
// half-tokenized DSN must fail closed, never yield guessed parameters.
func splitKeywordDSN(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQuote, esc, started := false, false, false
	flush := func() {
		if started {
			toks = append(toks, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
			started = true
		case r == '\\':
			esc = true
			started = true
		case r == '\'':
			inQuote = !inQuote
			started = true
		case !inQuote && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if inQuote {
		return nil, errors.New("datastore: keyword DSN has an unterminated quoted value")
	}
	if esc {
		return nil, errors.New("datastore: keyword DSN ends in a dangling backslash escape")
	}
	flush()
	return toks, nil
}
