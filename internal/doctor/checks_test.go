package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run1 runs a check and returns its findings (failing the test on an exec error).
func run1(t *testing.T, c Check, env *Env) []Finding {
	t.Helper()
	fs, err := c.Run(context.Background(), env)
	require.NoError(t, err)
	return fs
}

// runErr runs a check and returns only its error (for the could-not-run paths).
func runErr(t *testing.T, c Check, env *Env) error {
	t.Helper()
	_, err := c.Run(context.Background(), env)
	return err
}

// worst returns the highest severity in a finding slice.
func worst(fs []Finding) Severity {
	w := SeverityOK
	for _, f := range fs {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

// --- secrets -----------------------------------------------------------------

func TestSecretsCheck(t *testing.T) {
	t.Run("placeholder → critical", func(t *testing.T) {
		fs := run1(t, SecretsCheck{}, testEnv(map[string]string{"POSTGRES_PASSWORD": "CHANGE_ME"}))
		assert.Equal(t, SeverityCritical, worst(fs))
	})
	t.Run("too short → critical", func(t *testing.T) {
		fs := run1(t, SecretsCheck{}, testEnv(map[string]string{"CONTROL_VALKEY_PASSWORD": "short"}))
		assert.Equal(t, SeverityCritical, worst(fs))
	})
	t.Run("strong → ok", func(t *testing.T) {
		fs := run1(t, SecretsCheck{}, testEnv(map[string]string{
			"CONTROL_JWT_SECRET": "a-properly-long-random-jwt-secret-value-here",
		}))
		assert.Equal(t, SeverityOK, worst(fs))
	})
	t.Run("placeholder DB password inside DSN → critical", func(t *testing.T) {
		fs := run1(t, SecretsCheck{}, testEnv(map[string]string{
			"CONTROL_DATABASE_URL": "postgres://pm:CHANGE_ME@db:5432/pm",
		}))
		assert.Equal(t, SeverityCritical, worst(fs))
	})
}

// --- encryption key ----------------------------------------------------------

func TestEncryptionKeyCheck(t *testing.T) {
	assert.Equal(t, SeverityCritical, worst(run1(t, EncryptionKeyCheck{}, testEnv(nil))))
	assert.Equal(t, SeverityOK, worst(run1(t, EncryptionKeyCheck{},
		testEnv(map[string]string{"CONTROL_ENCRYPTION_KEY": "deadbeef"}))))
}

// --- cors --------------------------------------------------------------------

func TestCORSCheck(t *testing.T) {
	assert.Equal(t, SeverityCritical, worst(run1(t, CORSCheck{},
		testEnv(map[string]string{"CONTROL_CORS_ORIGINS": "https://ok.example, *"}))))
	assert.Equal(t, SeverityOK, worst(run1(t, CORSCheck{},
		testEnv(map[string]string{"CONTROL_CORS_ORIGINS": "https://ui.example"}))))
}

// --- ports -------------------------------------------------------------------

func TestPortsCheck(t *testing.T) {
	assert.Equal(t, SeverityWarning, worst(run1(t, PortsCheck{}, testEnv(nil))), "default :8082 binds all ifaces")
	assert.Equal(t, SeverityWarning, worst(run1(t, PortsCheck{},
		testEnv(map[string]string{"CONTROL_INTERNAL_LISTEN_ADDR": "0.0.0.0:8082"}))))
	assert.Equal(t, SeverityOK, worst(run1(t, PortsCheck{},
		testEnv(map[string]string{"CONTROL_INTERNAL_LISTEN_ADDR": "127.0.0.1:8082"}))))
}

// --- image tag ---------------------------------------------------------------

func TestImageTagCheck(t *testing.T) {
	assert.Equal(t, SeverityWarning, worst(run1(t, ImageTagCheck{},
		testEnv(map[string]string{"IMAGE_TAG": "latest"}))))
	assert.Equal(t, SeverityOK, worst(run1(t, ImageTagCheck{},
		testEnv(map[string]string{"IMAGE_TAG": "v2026.07"}))))
	t.Run("no .env file → info, not a false pass", func(t *testing.T) {
		fs := run1(t, ImageTagCheck{}, testEnv(nil)) // FromEnvFile defaults false
		assert.Equal(t, SeverityInfo, worst(fs))
	})
}

// --- cert perms --------------------------------------------------------------

func TestCertPermsCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ok.key")
	bad := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(good, []byte("x"), 0o400))
	require.NoError(t, os.WriteFile(bad, []byte("x"), 0o644))

	t.Run("0400 → ok", func(t *testing.T) {
		env := testEnv(nil)
		env.KeyFiles = []string{good}
		assert.Equal(t, SeverityOK, worst(run1(t, CertPermsCheck{}, env)))
	})
	t.Run("0644 → critical", func(t *testing.T) {
		env := testEnv(nil)
		env.KeyFiles = []string{bad}
		assert.Equal(t, SeverityCritical, worst(run1(t, CertPermsCheck{}, env)))
	})
	t.Run("nothing configured → info", func(t *testing.T) {
		env := testEnv(nil) // KeyFiles empty
		assert.Equal(t, SeverityInfo, worst(run1(t, CertPermsCheck{}, env)))
	})
	t.Run("configured key missing → critical, not a silent skip", func(t *testing.T) {
		env := testEnv(nil)
		env.KeyFiles = []string{filepath.Join(dir, "missing.key")}
		assert.Equal(t, SeverityCritical, worst(run1(t, CertPermsCheck{}, env)),
			"a key we were told about but cannot stat must fail closed")
	})
}

// --- cert expiry -------------------------------------------------------------

func writeTestCert(t *testing.T, path string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doctor-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
}

func TestCertExpiryCheck(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	mk := func(name string, nb, na time.Time) string {
		p := filepath.Join(dir, name)
		writeTestCert(t, p, nb, na)
		return p
	}
	envWith := func(paths ...string) *Env {
		e := testEnv(nil)
		e.CertFiles = paths
		return e
	}

	healthy := mk("ok.crt", now.AddDate(0, -1, 0), now.AddDate(1, 0, 0))   // ~90% remaining
	expired := mk("exp.crt", now.AddDate(-2, 0, 0), now.AddDate(-1, 0, 0)) // gone
	future := mk("fut.crt", now.AddDate(0, 1, 0), now.AddDate(1, 0, 0))    // not yet valid
	// 100-day lifetime, 95 days elapsed → ~5% remaining → past 80%.
	soon := mk("soon.crt", now.AddDate(0, 0, -95), now.AddDate(0, 0, 5))

	assert.Equal(t, SeverityOK, worst(run1(t, CertExpiryCheck{}, envWith(healthy))))
	assert.Equal(t, SeverityCritical, worst(run1(t, CertExpiryCheck{}, envWith(expired))))
	assert.Equal(t, SeverityCritical, worst(run1(t, CertExpiryCheck{}, envWith(future))))
	assert.Equal(t, SeverityWarning, worst(run1(t, CertExpiryCheck{}, envWith(soon))))

	t.Run("configured but missing → critical", func(t *testing.T) {
		assert.Equal(t, SeverityCritical, worst(run1(t, CertExpiryCheck{},
			envWith(filepath.Join(dir, "nope.crt")))))
	})
}

// --- live checks (fakes) -----------------------------------------------------

func TestDatastoresCheck(t *testing.T) {
	t.Run("both reachable → ok", func(t *testing.T) {
		env := testEnv(nil)
		env.DB, env.Cache = fakeDB{}, fakeCache{}
		assert.Equal(t, SeverityOK, worst(run1(t, DatastoresCheck{}, env)))
	})
	t.Run("postgres down → critical", func(t *testing.T) {
		env := testEnv(nil)
		env.DB, env.Cache = fakeDB{pingErr: errors.New("conn refused")}, fakeCache{}
		assert.Equal(t, SeverityCritical, worst(run1(t, DatastoresCheck{}, env)))
	})
	t.Run("nil handles → critical", func(t *testing.T) {
		assert.Equal(t, SeverityCritical, worst(run1(t, DatastoresCheck{}, testEnv(nil))))
	})
}

func TestQueuesCheck(t *testing.T) {
	t.Run("archived > 0 → warning", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{archived: map[string]int{"control:inbox": 3}}
		assert.Equal(t, SeverityWarning, worst(run1(t, QueuesCheck{}, env)))
	})
	t.Run("clean → ok", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{archived: map[string]int{"control:inbox": 0}}
		assert.Equal(t, SeverityOK, worst(run1(t, QueuesCheck{}, env)))
	})
	t.Run("no cache → info (skipped)", func(t *testing.T) {
		assert.Equal(t, SeverityInfo, worst(run1(t, QueuesCheck{}, testEnv(nil))))
	})
	t.Run("cache unreachable → info skip (DatastoresCheck owns the critical)", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{pingErr: errors.New("conn refused")}
		assert.Equal(t, SeverityInfo, worst(run1(t, QueuesCheck{}, env)))
	})
	t.Run("reachable but inspector fails → exec error (not a false pass)", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{archErr: errors.New("inspector boom")} // pingErr nil → reachable
		require.Error(t, runErr(t, QueuesCheck{}, env))
	})
}

func TestSearchCheck(t *testing.T) {
	t.Run("missing index → critical", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{missing: []string{"idx:devices"}, schemaCurrent: true}
		assert.Equal(t, SeverityCritical, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("stale schema → warning", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{schemaCurrent: false}
		assert.Equal(t, SeverityWarning, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("all present + current + fresh reconcile → ok", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{
			schemaCurrent: true,
			reconcileOK:   true,
			lastReconcile: env.now().Add(-30 * time.Minute), // within 2× the 1h default
		}
		assert.Equal(t, SeverityOK, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("stale reconcile heartbeat → warning (dead/stuck indexer)", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{
			schemaCurrent: true,
			reconcileOK:   true,
			lastReconcile: env.now().Add(-3 * time.Hour), // > 2× the 1h default
		}
		assert.Equal(t, SeverityWarning, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("stale reconcile but schema current uses the configured interval", func(t *testing.T) {
		env := testEnv(map[string]string{"INDEXER_RECONCILE_INTERVAL": "6h"})
		env.Cache = fakeCache{
			schemaCurrent: true,
			reconcileOK:   true,
			lastReconcile: env.now().Add(-3 * time.Hour), // < 2×6h → still fresh
		}
		assert.Equal(t, SeverityOK, worst(run1(t, SearchCheck{}, env)), "horizon derives from INDEXER_RECONCILE_INTERVAL")
	})
	t.Run("no heartbeat present → no false warning", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{schemaCurrent: true} // reconcileOK:false
		assert.Equal(t, SeverityOK, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("cache unreachable → info skip", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{pingErr: errors.New("down")}
		assert.Equal(t, SeverityInfo, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("reachable but FT.INFO fails → exec error", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{missingErr: errors.New("RediSearch module absent")}
		require.Error(t, runErr(t, SearchCheck{}, env))
	})
	t.Run("reachable but heartbeat read fails → exec error", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{reconcileErr: errors.New("bad heartbeat value")}
		require.Error(t, runErr(t, SearchCheck{}, env))
	})
	t.Run("present index rejects queries → critical (functional probe)", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{
			schemaCurrent: true,
			reconcileOK:   true,
			lastReconcile: env.now().Add(-1 * time.Minute),
			// FT.INFO says the index is present, but it rejects the match-all
			// query — the exact failure the list pages hit. State checks would
			// pass; the functional probe catches it.
			rejected: map[string]string{"idx:devices": "Invalid query string syntax"},
		}
		assert.Equal(t, SeverityCritical, worst(run1(t, SearchCheck{}, env)))
	})
	t.Run("query probe errors (reachable) → exec error", func(t *testing.T) {
		env := testEnv(nil)
		env.Cache = fakeCache{schemaCurrent: true, rejectErr: errors.New("probe boom")}
		require.Error(t, runErr(t, SearchCheck{}, env))
	})
}

func TestAdminCheck(t *testing.T) {
	t.Run("config default email → warning", func(t *testing.T) {
		assert.Equal(t, SeverityWarning, worst(run1(t, AdminCheck{},
			testEnv(map[string]string{"CONTROL_ADMIN_EMAIL": defaultAdminEmail}))))
	})
	t.Run("db has default admin → warning", func(t *testing.T) {
		env := testEnv(nil)
		env.DB = fakeDB{adminExists: true}
		assert.Equal(t, SeverityWarning, worst(run1(t, AdminCheck{}, env)))
	})
	t.Run("neither → ok", func(t *testing.T) {
		env := testEnv(map[string]string{"CONTROL_ADMIN_EMAIL": "ops@corp.example"})
		env.DB = fakeDB{adminExists: false}
		assert.Equal(t, SeverityOK, worst(run1(t, AdminCheck{}, env)))
	})
	t.Run("db unreachable → info skip (DatastoresCheck owns the critical)", func(t *testing.T) {
		env := testEnv(map[string]string{"CONTROL_ADMIN_EMAIL": "ops@corp.example"})
		env.DB = fakeDB{pingErr: errors.New("conn refused")}
		assert.Equal(t, SeverityInfo, worst(run1(t, AdminCheck{}, env)))
	})
	t.Run("db reachable but query fails → exec error (not a false ok)", func(t *testing.T) {
		env := testEnv(map[string]string{"CONTROL_ADMIN_EMAIL": "ops@corp.example"})
		env.DB = fakeDB{adminErr: errors.New("query boom")} // pingErr nil → reachable
		require.Error(t, runErr(t, AdminCheck{}, env))
	})
	t.Run("no db configured + clean env → info skip (db side unverifiable)", func(t *testing.T) {
		env := testEnv(map[string]string{"CONTROL_ADMIN_EMAIL": "ops@corp.example"})
		assert.Equal(t, SeverityInfo, worst(run1(t, AdminCheck{}, env)))
	})
}
