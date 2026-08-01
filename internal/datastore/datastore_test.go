package datastore

import (
	"testing"
)

func TestRequirePostgresTLS(t *testing.T) {
	const certs = "&sslrootcert=/c/ca.crt&sslcert=/c/pg.crt&sslkey=/c/pg.key"
	cases := []struct {
		name string
		dsn  string
		ok   bool
	}{
		{"url verify-full + certs", "postgres://u:p@h:5432/db?sslmode=verify-full" + certs, true},
		{"keyword verify-full + certs", "host=h dbname=db sslmode=verify-full sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key", true},
		{"sslmode=disable rejected", "postgres://u:p@h:5432/db?sslmode=disable", false},
		{"absent sslmode rejected", "postgres://u:p@h:5432/db", false},
		{"verify-full but no client cert", "postgres://u:p@h:5432/db?sslmode=verify-full&sslrootcert=/c/ca.crt", false},
		{"require (not verify-full) rejected", "postgres://u:p@h:5432/db?sslmode=require" + certs, false},
		// Fail-closed regression: the real sslmode is disable; a quoted value
		// embedding "sslmode=verify-full" must NOT be split into a spurious token
		// that overwrites it (a bare strings.Fields split would wrongly accept).
		{"keyword quoted value cannot forge sslmode",
			"host=h dbname=db sslmode=disable sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key application_name='x sslmode=verify-full'",
			false},
		// A valid keyword DSN must not be mis-routed through URL parsing just
		// because a quoted value contains "://" (cr 2026-07-19).
		{"keyword value containing :// stays keyword-parsed",
			"host=h dbname=db sslmode=verify-full sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key password='https://not-a-uri'",
			true},
		// libpq errors on an unterminated quoted value; so do we (fail closed).
		{"unterminated quote rejected",
			"host=h dbname=db sslmode=verify-full sslrootcert=/c/ca.crt sslcert=/c/pg.crt sslkey=/c/pg.key application_name='oops",
			false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequirePostgresTLS(tc.dsn)
			if tc.ok && err != nil {
				t.Errorf("expected acceptance, got: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("expected fail-closed rejection, got nil")
			}
		})
	}
}
