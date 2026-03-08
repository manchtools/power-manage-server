// Certgen generates the internal PKI certificates for Power Manage deployment.
//
// It creates a CA certificate, a gateway server certificate, and a control
// server certificate — all using Go's crypto/x509 package so there are no
// encoding mismatches during TLS verification.
//
// Usage:
//
//	certgen -dir ./certs -gateway-domain gw.example.com
package main

import (
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
	flag.Parse()

	if *gatewayDomain == "" && !*caOnly {
		fmt.Fprintln(os.Stderr, "error: -gateway-domain is required (or use -ca-only)")
		os.Exit(1)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fatal("create output directory: %v", err)
	}

	// Generate CA
	caKey, caCert := generateCA(*dir)
	fmt.Println("Generated CA certificate")

	if *caOnly {
		return
	}

	// Generate gateway server certificate
	generateServerCert(*dir, "gateway", []string{*gatewayDomain}, caKey, caCert)
	fmt.Printf("Generated gateway certificate (SAN: %s)\n", *gatewayDomain)

	// Generate control server certificate (Docker internal hostname)
	generateServerCert(*dir, "control", []string{"control", "localhost"}, caKey, caCert)
	fmt.Println("Generated control certificate (SAN: control, localhost)")
}

func generateCA(dir string) (*rsa.PrivateKey, *x509.Certificate) {
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	// Generate RSA 4096 key
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

func generateServerCert(dir, name string, dnsNames []string, caKey *rsa.PrivateKey, caCert *x509.Certificate) {
	keyPath := filepath.Join(dir, name+".key")
	certPath := filepath.Join(dir, name+".crt")

	// Generate ECDSA P-256 key
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
