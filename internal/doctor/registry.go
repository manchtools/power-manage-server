package doctor

// DefaultChecks is the full check suite, in display order. Adding a check here is
// all that's needed to wire it; the self-discovering completeness test enforces
// that each one is exercised by a test.
func DefaultChecks() []Check {
	return []Check{
		SecretsCheck{},
		EncryptionKeyCheck{},
		CertPermsCheck{},
		CertExpiryCheck{},
		CORSCheck{},
		PortsCheck{},
		ImageTagCheck{},
		DatastoresCheck{},
		QueuesCheck{},
		SearchCheck{},
		TerminalCheck{},
		AdminCheck{},
		DEKInvariantCheck{},
		ProjectionDriftCheck{},
	}
}
