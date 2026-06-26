package doctor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CertPermsCheck — private key files must not be group/world-readable
// (spec 15, criterion 6).
type CertPermsCheck struct{}

func (CertPermsCheck) ID() string { return "cert_perms" }

func (c CertPermsCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	// Nothing configured to inspect is a genuine "not applicable", not a pass.
	if len(env.KeyFiles) == 0 {
		return []Finding{info(c.ID(), "no private key files configured to inspect")}, nil
	}
	var findings []Finding
	for _, path := range env.KeyFiles {
		fi, err := os.Stat(path)
		if err != nil {
			// These paths are configured (CONTROL_*_KEY set, or the documented
			// default that existed at resolution). A key we were told about but
			// cannot stat — missing, or its directory unreadable — means we cannot
			// verify a security-relevant file: fail closed, never silently skip.
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("cannot inspect private key %s", filepath.Base(path)),
				"ensure the configured key exists and is owner-readable ("+err.Error()+")"))
			continue
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("private key %s is group/other-accessible (mode %#o)", filepath.Base(path), perm),
				"chmod 0400 the key and restrict its directory"))
		}
	}
	if len(findings) == 0 {
		return []Finding{ok(c.ID(), fmt.Sprintf("all %d private key file(s) are 0400-restricted", len(env.KeyFiles)))}, nil
	}
	return findings, nil
}

// CertExpiryCheck — CA/service certs: missing/expired/not-yet-valid → critical;
// past 80% of their own lifetime (< 20% remaining) → warning. The horizon is
// derived from each cert's lifetime, not a fixed day count (spec 15, criterion 7).
type CertExpiryCheck struct{}

func (CertExpiryCheck) ID() string { return "cert_expiry" }

func (c CertExpiryCheck) Run(_ context.Context, env *Env) ([]Finding, error) {
	var findings []Finding
	now := env.now()
	checked := 0
	for _, path := range env.CertFiles {
		base := filepath.Base(path)
		cert, err := parseCertFile(path)
		if err != nil {
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("certificate %s is missing or unparseable", base),
				"ensure the cert exists and is valid PEM ("+err.Error()+")"))
			continue
		}
		checked++
		switch {
		case now.Before(cert.NotBefore):
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("certificate %s is not yet valid", base),
				"check the system clock and the cert's NotBefore"))
		case now.After(cert.NotAfter):
			findings = append(findings, crit(c.ID(),
				fmt.Sprintf("certificate %s has expired", base),
				"re-issue/replace the certificate"))
		case remainingFraction(cert, now) < 0.20:
			findings = append(findings, warn(c.ID(),
				fmt.Sprintf("certificate %s is past 80%% of its lifetime", base),
				"rotate/replace it — auto-rotation should already have fired"))
			findings[len(findings)-1].Detail = "expires " + cert.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	if checked == 0 && len(findings) == 0 {
		return []Finding{info(c.ID(), "no certificate files found to inspect")}, nil
	}
	if len(findings) == 0 {
		return []Finding{ok(c.ID(), fmt.Sprintf("all %d certificate(s) valid and within lifetime", checked))}, nil
	}
	return findings, nil
}

// remainingFraction returns the fraction of the cert's total validity window that
// is still left (1.0 just issued, 0.0 at expiry). A non-positive lifetime returns
// 0 (treated as "at/over the limit").
func remainingFraction(cert *x509.Certificate, now time.Time) float64 {
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return 0
	}
	return cert.NotAfter.Sub(now).Seconds() / total.Seconds()
}

// parseCertFile reads a PEM file and parses its first CERTIFICATE block.
func parseCertFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("no CERTIFICATE block in %s", filepath.Base(path))
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}
