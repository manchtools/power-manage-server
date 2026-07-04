package payloads

// TOTPSetupInitiated is the wire shape for TOTPSetupInitiated.
// secret_encrypted is the AES-GCM ciphertext of the user's TOTP
// secret; backup_codes_hash is the slice of bcrypt hashes for the
// one-time backup codes generated during setup.
type TOTPSetupInitiated struct {
	SecretEncrypted string   `json:"secret_encrypted"`
	BackupCodesHash []string `json:"backup_codes_hash"`
}

// TOTPBackupCodesRegenerated is the wire shape for the backup-code
// regeneration event. Same shape as TOTPSetupInitiated minus the
// secret — the user is keeping the existing TOTP secret but minting
// fresh backup codes.
type TOTPBackupCodesRegenerated struct {
	BackupCodesHash []string `json:"backup_codes_hash"`
}

// TOTPVerified is the wire shape for TOTPVerified. Deliberately empty
// — the projector flips the enabled flag off the event's stream_id
// alone; the zero struct marshals to `{}`, byte-identical to the
// legacy map[string]any{} payload.
type TOTPVerified struct{}

// TOTPDisabled is the wire shape for TOTPDisabled. admin marks the
// AdminDisableUserTOTP path (audit context: the actor disabled someone
// ELSE's TOTP); the self-service path emits the zero struct, which
// marshals to `{}` exactly like the legacy payload.
type TOTPDisabled struct {
	Admin bool `json:"admin,omitempty"`
}

// TOTPBackupCodeUsed is the wire shape for TOTPBackupCodeUsed. Index
// is the position of the consumed code in the backup_codes_hash slice
// — the projector NULLs that slot so the code is single-use.
type TOTPBackupCodeUsed struct {
	Index int `json:"index"`
}
