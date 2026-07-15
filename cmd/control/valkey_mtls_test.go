package main

import "testing"

// TestValkeyClientTLS_NilWhenUnset_ErrorWhenPartial pins the spec-32 fail-closed
// posture of the datastore-mTLS config builder: no cert paths → nil (dev; boot
// enforces mTLS separately), and any PARTIAL set is a hard error rather than a
// silent plaintext downgrade. The valid-cert path is covered by the datastore
// mTLS integration tests.
func TestValkeyClientTLS_NilWhenUnset_ErrorWhenPartial(t *testing.T) {
	if cfg, err := valkeyClientTLS(&Config{}); err != nil || cfg != nil {
		t.Errorf("unset cert paths → (nil, nil), got (%v, %v)", cfg, err)
	}
	partial := []*Config{
		{ValkeyTLSCert: "/c.crt"},
		{ValkeyTLSKey: "/c.key"},
		{ValkeyTLSCA: "/ca.crt"},
		{ValkeyTLSCert: "/c.crt", ValkeyTLSKey: "/c.key"}, // missing CA
	}
	for _, c := range partial {
		if _, err := valkeyClientTLS(c); err == nil {
			t.Errorf("partial TLS config %+v must be rejected (fail closed)", c)
		}
	}
}
