// Package config file env.go — env-var override helpers shared
// between cmd/control, cmd/gateway, cmd/indexer (audit F017).
//
// Each helper reads ONE env var, parses it with the appropriate
// validator, and overrides the target on success. Empty / unset
// values are no-ops (caller's pre-set default stays). Invalid
// values log a warning and leave the target unchanged so a misset
// production env var degrades gracefully rather than panicking at
// startup.
//
// History: cmd/control/main.go originally owned local copies of
// these helpers; cmd/indexer/main.go open-coded the same shape
// inline. Audit F017 promoted them to this package so the three
// binaries (and any future binary) share one parsing contract.
package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvString overrides target with the env-var value if set.
// Empty string is treated as "unset" (consistent with the historic
// control / gateway behaviour — explicit emptiness is rejected at
// the validator step, not silently honoured here).
func EnvString(target *string, key string) {
	if v := os.Getenv(key); v != "" {
		*target = v
	}
}

// EnvBool sets target based on the env-var value matching one of
// trueValues / falseValues. Unrecognized non-empty values log a
// warning and leave target alone.
func EnvBool(target *bool, key string, trueValues, falseValues []string) {
	v := os.Getenv(key)
	if v == "" {
		return
	}
	for _, tv := range trueValues {
		if v == tv {
			*target = true
			return
		}
	}
	for _, fv := range falseValues {
		if v == fv {
			*target = false
			return
		}
	}
	slog.Warn("unrecognized boolean env var value, keeping default", "key", key, "value", v)
}

// EnvDuration overrides target with the parsed duration if the
// env var is set. Parse errors log a warning and leave target alone.
func EnvDuration(target *time.Duration, key string) {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			slog.Warn("invalid duration for env var, keeping default", "key", key, "value", v, "error", err)
			return
		}
		*target = d
	}
}

// EnvCSV overrides target with a comma-separated env var, trimming
// whitespace and filtering empty entries. Returns nil for an
// all-empty list (rather than a one-element slice with an empty
// string) so downstream `len() == 0` checks behave intuitively.
func EnvCSV(target *[]string, key string) {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		var filtered []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				filtered = append(filtered, p)
			}
		}
		*target = filtered
	}
}

// EnvInt overrides target with the parsed integer if the env var is
// set. Parse errors log a warning and leave target alone.
func EnvInt(target *int, key string) {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			slog.Warn("invalid integer for env var, keeping default", "key", key, "value", v, "error", err)
			return
		}
		*target = n
	}
}
