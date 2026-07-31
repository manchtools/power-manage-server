package mtls

// FingerprintFromCertForTest exposes the package-private fingerprintFromCert to
// the EXTERNAL mtls_test package.
//
// The seam exists for one reason: fingerprintFromCert is a second, independent
// implementation of ca.FingerprintFromCert (ca imports mtls, so mtls cannot
// import ca back), and both feed the same revoked_certificates lookup — one
// writes the fingerprint that gets revoked, the other derives the fingerprint
// checked at the handshake. If they ever disagree, revocation silently stops
// working with nothing red. Proving they agree needs a test that can call both,
// which means importing ca — impossible from an internal test file in package
// mtls (import cycle), possible from package mtls_test.
var FingerprintFromCertForTest = fingerprintFromCert
