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
