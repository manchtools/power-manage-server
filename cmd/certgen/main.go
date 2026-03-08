// Certgen generates the internal PKI certificates for Power Manage deployment.
//
// It creates a CA certificate, a gateway server certificate, and a control
// server certificate — all using Go's crypto/x509 package so there are no
// encoding mismatches during TLS verification.
//
// Three modes of operation:
//
//  1. Self-contained (default): generates CA + server certs
//     certgen -dir ./certs -gateway-domain gw.example.com
//
//  2. External CA: uses an existing CA cert+key to sign server certs
//     certgen -dir ./certs -gateway-domain gw.example.com -ca-cert ca.crt -ca-key ca.key
//
//  3. CSR-only: generates keys + CSRs for external signing (HSM, Vault, corporate PKI)
//     certgen -dir ./certs -gateway-domain gw.example.com -csr-only
//     Then sign the CSRs externally and place the signed certs back as gateway.crt / control.crt.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", "certs", "output directory for certificates")
	gatewayDomain := flag.String("gateway-domain", "", "gateway server domain (SAN)")
	caOnly := flag.Bool("ca-only", false, "only generate CA certificate")
	caCertPath := flag.String("ca-cert", "", "path to existing CA certificate (external CA mode)")
	caKeyPath := flag.String("ca-key", "", "path to existing CA private key (external CA mode)")
	csrOnly := flag.Bool("csr-only", false, "generate keys and CSRs only (for external signing)")
	flag.Parse()

	if *gatewayDomain == "" && !*caOnly {
		fmt.Fprintln(os.Stderr, "error: -gateway-domain is required (or use -ca-only)")
		os.Exit(1)
	}

	if (*caCertPath == "") != (*caKeyPath == "") {
		fmt.Fprintln(os.Stderr, "error: -ca-cert and -ca-key must be used together")
		os.Exit(1)
	}

	if *csrOnly && *caCertPath != "" {
		fmt.Fprintln(os.Stderr, "error: -csr-only and -ca-cert/-ca-key are mutually exclusive")
		os.Exit(1)
	}

	if *csrOnly && *caOnly {
		fmt.Fprintln(os.Stderr, "error: -csr-only and -ca-only are mutually exclusive")
		os.Exit(1)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal("create output directory: %v", err)
	}

	// CSR-only mode: generate keys and CSRs for external signing.
	if *csrOnly {
		generateCSR(*dir, "gateway", []string{*gatewayDomain})
		fmt.Printf("Generated gateway CSR (SAN: %s)\n", *gatewayDomain)

		generateCSR(*dir, "control", []string{"control", "localhost"})
		fmt.Println("Generated control CSR (SAN: control, localhost)")

		fmt.Println()
		fmt.Println("Sign the CSRs with your CA and place the signed certificates as:")
		fmt.Printf("  %s\n", filepath.Join(*dir, "gateway.crt"))
		fmt.Printf("  %s\n", filepath.Join(*dir, "control.crt"))
		fmt.Println()
		fmt.Println("Also place your CA certificate as:")
		fmt.Printf("  %s\n", filepath.Join(*dir, "ca.crt"))
		return
	}

	// Load or generate the CA.
	var caKey crypto.Signer
	var caCert *x509.Certificate

	if *caCertPath != "" {
		// External CA mode: load existing CA cert+key.
		caKey, caCert = loadCA(*caCertPath, *caKeyPath)
		fmt.Println("Loaded external CA certificate")
	} else {
		// Self-contained mode: generate new CA.
		caKey, caCert = generateCA(*dir)
		fmt.Println("Generated CA certificate")
	}

	if *caOnly {
		return
	}

	// Sign server certificates with the CA.
	signServerCert(*dir, "gateway", []string{*gatewayDomain}, caKey, caCert)
	fmt.Printf("Generated gateway certificate (SAN: %s)\n", *gatewayDomain)

	signServerCert(*dir, "control", []string{"control", "localhost"}, caKey, caCert)
	fmt.Println("Generated control certificate (SAN: control, localhost)")
}

// loadCA loads a CA certificate and private key from PEM files.
// The private key is parsed as crypto.Signer, supporting RSA, ECDSA, and Ed25519.
func loadCA(certPath, keyPath string) (crypto.Signer, *x509.Certificate) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		fatal("read CA certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		fatal("CA certificate file contains no PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fatal("parse CA certificate: %v", err)
	}
	if !cert.IsCA {
		fatal("certificate at %s is not a CA certificate", certPath)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fatal("read CA key: %v", err)
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		fatal("parse CA key: %v", err)
	}

	return key, cert
}

// parsePrivateKey attempts to parse a PEM-encoded private key as crypto.Signer.
// Supports PKCS#8, PKCS#1 (RSA), and SEC 1 (EC) formats.
func parsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}

	// Try PKCS#8 first (generic format, works with RSA, ECDSA, Ed25519).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("PKCS#8 key does not implement crypto.Signer")
	}

	// Try EC private key (SEC 1 / RFC 5915).
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try RSA private key (PKCS#1).
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported private key format")
}

func generateCA(dir string) (crypto.Signer, *x509.Certificate) {
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fatal("generate CA key: %v", err)
	}

	serial := newSerial()
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Power Manage Internal CA",
			Organization: []string{"Power Manage"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fatal("create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fatal("parse CA certificate: %v", err)
	}

	writeKeyFile(keyPath, x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY", 0o600)
	writeCertFile(certPath, certDER, 0o644)

	return key, cert
}

// generateCSR generates an ECDSA P-256 key and a certificate signing request.
func generateCSR(dir, name string, dnsNames []string) {
	keyPath := filepath.Join(dir, name+".key")
	csrPath := filepath.Join(dir, name+".csr")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate %s key: %v", name, err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"Power Manage"},
		},
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		fatal("create %s CSR: %v", name, err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fatal("marshal %s key: %v", name, err)
	}

	writeKeyFile(keyPath, keyDER, "EC PRIVATE KEY", 0o600)

	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := os.WriteFile(csrPath, data, 0o644); err != nil {
		fatal("write %s: %v", csrPath, err)
	}
}

// signServerCert generates a key, creates a certificate, and signs it with the CA.
func signServerCert(dir, name string, dnsNames []string, caKey crypto.Signer, caCert *x509.Certificate) {
	keyPath := filepath.Join(dir, name+".key")
	certPath := filepath.Join(dir, name+".crt")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate %s key: %v", name, err)
	}

	serial := newSerial()
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"Power Manage"},
		},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(825 * 24 * time.Hour), // 825 days
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		fatal("create %s certificate: %v", name, err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fatal("marshal %s key: %v", name, err)
	}

	writeKeyFile(keyPath, keyDER, "EC PRIVATE KEY", 0o600)
	writeCertFile(certPath, certDER, 0o644)
}

func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fatal("generate serial number: %v", err)
	}
	return serial
}

func writeKeyFile(path string, der []byte, pemType string, mode os.FileMode) {
	data := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		fatal("write %s: %v", path, err)
	}
}

func writeCertFile(path string, der []byte, mode os.FileMode) {
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		fatal("write %s: %v", path, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
