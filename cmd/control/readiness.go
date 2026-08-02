package main

import (
	"context"
	"errors"
	"fmt"
)

const readinessFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

type readinessStore interface {
	Ping(context.Context) error
}

type readinessRevocationChecker interface {
	IsRevoked(context.Context, string) (bool, error)
}

// checkReadiness verifies the dependencies whose availability can change
// after startup. Schema and key material are validated while control starts.
func checkReadiness(
	ctx context.Context,
	st readinessStore,
	revocations readinessRevocationChecker,
	artifactPath string,
) error {
	if ctx == nil || st == nil || revocations == nil {
		return errors.New("readiness dependencies are required")
	}
	if err := st.Ping(ctx); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	if _, err := revocations.IsRevoked(ctx, readinessFingerprint); err != nil {
		return fmt.Errorf("revocation enforcement: %w", err)
	}
	if err := validateWritableDirectory("artifact path", artifactPath); err != nil {
		return fmt.Errorf("artifact path: %w", err)
	}
	return nil
}
