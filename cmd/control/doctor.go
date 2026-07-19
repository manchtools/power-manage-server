package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/manchtools/power-manage/server/internal/datastore"
	"github.com/manchtools/power-manage/server/internal/doctor"
)

// runDoctor implements `control doctor [--json] [--env-file path]`:
// a standalone, read-only health/security-posture pass. Returns the process exit
// code (0 ok/info · 1 warning · 100 critical · 2 could-not-run — spec 15).
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit findings as JSON for CI/monitoring")
	envFile := fs.String("env-file", ".env", "deploy .env file to inspect (skipped if absent)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // `doctor -h` is a successful help request, not a failure
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "doctor: unexpected argument(s): %v\n", fs.Args())
		return 2
	}

	// Merge the process env with the deploy .env file (the file wins — it is the
	// operator's stored config, the source of truth for what they configured).
	vars := doctor.ProcessEnv()
	fromFile := false
	if dotenv, err := doctor.LoadEnvFile(*envFile); err != nil {
		fmt.Fprintf(os.Stderr, "doctor: could not read %s: %v\n", *envFile, err)
		return 2
	} else if dotenv != nil {
		vars = doctor.MergeVars(vars, dotenv)
		fromFile = true
	}

	env := doctor.NewEnv(vars)
	env.FromEnvFile = fromFile
	env.CertFiles, env.KeyFiles = resolveCertPaths(vars)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Live probes connect lazily; a nil probe (bad/empty config) surfaces as a
	// Critical finding from the datastores check, not a crash.
	if db, err := doctor.NewPGProbe(ctx, vars["CONTROL_DATABASE_URL"]); err == nil {
		env.DB = db
		defer db.Close()
	}
	valkeyDB := 0
	if raw := vars["CONTROL_VALKEY_DB"]; raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			// Silently coercing a bad value to DB 0 would probe the wrong database
			// and report a false-positive health result — fail as a config error.
			fmt.Fprintf(os.Stderr, "doctor: CONTROL_VALKEY_DB %q is not a valid integer: %v\n", raw, err)
			return 2
		}
		valkeyDB = n
	}
	// spec 32: probe Valkey the same way the live server connects — as the ACL
	// user over mutual TLS. A partial cert set errors (logged below); an entirely
	// absent one yields nil WITHOUT an error. Both mean a plaintext probe, so
	// valkeyProbeCreds withholds the ACL credentials on any nil tlsCfg — they
	// must never cross an unencrypted socket. The posture finding in the report
	// surfaces the plaintext configuration as a Warning.
	valkeyTLS, err := datastore.ValkeyClientTLSFromFiles(vars["CONTROL_VALKEY_TLS_CERT"], vars["CONTROL_VALKEY_TLS_KEY"], vars["CONTROL_VALKEY_TLS_CA"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: valkey mTLS config incomplete, probing without TLS and without ACL credentials: %v\n", err)
	}
	valkeyUser, valkeyPass := valkeyProbeCreds(valkeyTLS, vars["CONTROL_VALKEY_USERNAME"], vars["CONTROL_VALKEY_PASSWORD"])
	if cache, err := doctor.NewValkeyProbe(vars["CONTROL_VALKEY_ADDR"], valkeyUser, valkeyPass, valkeyDB, valkeyTLS); err == nil {
		env.Cache = cache
		defer cache.Close()
	}
	env.Posture = datastorePosture(vars, valkeyTLS)

	report := doctor.Run(ctx, env, doctor.DefaultChecks())

	if *jsonOut {
		if err := doctor.RenderJSON(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: render json: %v\n", err)
			return 2
		}
	} else {
		doctor.RenderHuman(os.Stdout, report)
	}
	return report.ExitCode()
}

// valkeyProbeCreds returns the ACL credentials the probe may use. A nil TLS
// config — cert set absent OR incomplete — means a plaintext dial, so the
// credentials are withheld: they must never cross an unencrypted socket.
func valkeyProbeCreds(tlsCfg *tls.Config, user, pass string) (string, string) {
	if tlsCfg == nil {
		return "", ""
	}
	return user, pass
}

// datastorePosture derives the spec-32 auth posture the doctor reports. Safe
// fields only (users, modes, cert CNs) — never credentials or raw DSNs.
func datastorePosture(vars map[string]string, valkeyTLS *tls.Config) *doctor.DatastorePosture {
	p := &doctor.DatastorePosture{
		ValkeyUser:   vars["CONTROL_VALKEY_USERNAME"],
		ValkeyMTLS:   valkeyTLS != nil,
		ValkeyCertCN: clientCertCN(valkeyTLS),
	}
	dsn := vars["CONTROL_DATABASE_URL"]
	sslmode, sslcert := datastore.PostgresTLSPosture(dsn)
	if datastore.RequirePostgresTLS(dsn) == nil {
		p.PostgresMTLS = true
		p.PostgresCertCN = pemCertCN(sslcert)
	} else if sslmode == "verify-full" {
		p.PostgresDetail = "verify-full without complete client-cert material"
	} else {
		p.PostgresDetail = fmt.Sprintf("sslmode=%q", sslmode)
	}
	return p
}

// clientCertCN returns the CN of cfg's client certificate. Best-effort display
// value: "" (posture shown as unknown) on a nil config or unparseable cert —
// the mTLS on/off verdict is carried separately, so no error is swallowed.
func clientCertCN(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		return ""
	}
	return leaf.Subject.CommonName
}

// pemCertCN reads a PEM certificate file and returns its CN. Same best-effort
// display contract as clientCertCN.
func pemCertCN(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return leaf.Subject.CommonName
}

// resolveCertPaths returns the cert/key files to inspect. A path is included when
// its env var is explicitly set (configured → a missing file is a real problem)
// OR the documented default exists (so an in-container run checks the mounted
// certs); an unset var whose default is absent is skipped, so a host run without
// the certs mounted doesn't produce false "missing cert" criticals.
func resolveCertPaths(vars map[string]string) (certs, keys []string) {
	add := func(list *[]string, envKey, def string) {
		if v := vars[envKey]; v != "" {
			*list = append(*list, v)
		} else if _, err := os.Stat(def); err == nil {
			*list = append(*list, def)
		}
	}
	add(&certs, "CONTROL_CA_CERT", "/certs/ca.crt")
	add(&certs, "CONTROL_INTERNAL_TLS_CERT", "/certs/control.crt")
	add(&keys, "CONTROL_CA_KEY", "/certs/ca.key")
	add(&keys, "CONTROL_INTERNAL_TLS_KEY", "/certs/control.key")
	return certs, keys
}
