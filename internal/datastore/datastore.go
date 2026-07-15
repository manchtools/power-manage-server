// Package datastore holds the client-side mTLS/auth plumbing for the control
// server's connections to Valkey and Postgres (spec 32: datastore auth
// hardening). It is the CLIENT counterpart to internal/mtls (which builds the
// SERVER-side TLS configs the gateway presents): these helpers build the client
// config a datastore connection presents, and fail closed if a connection is
// configured for cleartext rather than mutual TLS.
//
// Spec 32 has NO plaintext fallback — mutual TLS is the only supported posture,
// reusing the spec-31 CA as the single trust root. These are the reusable
// primitives; wiring them into the concrete client sites (with the TLS-capable
// test harness) is the next implementation phase.
package datastore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ValkeyClientTLS builds the client mTLS config a Valkey connection presents:
// the component's CA-signed client certificate, server verification pinned to
// the internal CA ONLY (RootCAs, never system roots — a public cert with a
// matching name cannot impersonate the datastore), TLS 1.3 floor. Mirrors the
// agent's gateway-facing strict-CA trust in both directions.
func ValkeyClientTLS(certPEM, keyPEM, caPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("datastore: parse client certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("datastore: failed to parse CA certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ValkeyClientTLSFromFiles builds the datastore client mTLS config from cert
// file paths (the shape every binary's config carries). Returns (nil, nil) when
// all three paths are empty — mTLS not configured, so the caller decides whether
// that is allowed (dev) or a fail-closed boot error (production). A partial set
// (some paths but not all) is always an error: it signals a half-finished mTLS
// config that must not silently degrade to plaintext. Otherwise it reads the
// files and delegates to ValkeyClientTLS.
func ValkeyClientTLSFromFiles(certPath, keyPath, caPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" && caPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, errors.New("datastore: Valkey TLS cert, key, and CA must all be set for mTLS (spec 32)")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("datastore: read valkey client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("datastore: read valkey client key: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("datastore: read valkey CA: %w", err)
	}
	return ValkeyClientTLS(certPEM, keyPEM, caPEM)
}

// RequirePostgresTLS returns an error unless connString is configured for mutual
// TLS: sslmode=verify-full with the client-cert material (sslrootcert/sslcert/
// sslkey) present. A sslmode=disable or absent DSN, or verify-full without the
// cert params, is a boot-time fail-closed error — spec 32 permits no plaintext
// downgrade. pgx passes these libpq params through natively, so this validates
// posture rather than rewriting the DSN.
func RequirePostgresTLS(connString string) error {
	params, err := dsnParams(connString)
	if err != nil {
		return err
	}
	if got := params["sslmode"]; got != "verify-full" {
		return fmt.Errorf("datastore: Postgres sslmode=%q — spec 32 requires verify-full (mutual TLS, no plaintext fallback)", got)
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
	if strings.Contains(connString, "://") {
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
	for _, kv := range strings.Fields(connString) {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = strings.Trim(kv[i+1:], "'\"")
		}
	}
	return out, nil
}
