package api

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/manchtools/power-manage/server/internal/eventtypes"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
)

// TestTOTPSecretAndBackupCodesRedacted pins WS10 #8: TOTP setup and
// backup-code regeneration events must not expose the secret ciphertext
// or the backup-code hashes through the audit log.
func TestTOTPSecretAndBackupCodesRedacted(t *testing.T) {
	setup, err := json.Marshal(payloads.TOTPSetupInitiated{
		SecretEncrypted: "enc:v2:totpsecretblob",
		BackupCodesHash: []string{"$2a$bchash1", "$2a$bchash2"},
	})
	assert.NoError(t, err)
	out := redactEventData("totp", string(eventtypes.TOTPSetupInitiated), setup)
	assert.Contains(t, out, "[REDACTED]")
	assert.NotContains(t, out, "totpsecretblob")
	assert.NotContains(t, out, "bchash1")

	regen, err := json.Marshal(payloads.TOTPBackupCodesRegenerated{BackupCodesHash: []string{"$2a$regenhash"}})
	assert.NoError(t, err)
	out2 := redactEventData("totp", string(eventtypes.TOTPBackupCodesRegenerated), regen)
	assert.Contains(t, out2, "[REDACTED]")
	assert.NotContains(t, out2, "regenhash")

	// A TOTP event with no secret payload passes through unchanged.
	out3 := redactEventData("totp", string(eventtypes.TOTPVerified), []byte(`{"verified":true}`))
	assert.Contains(t, out3, "verified")
}

// TestEveryTOTPEventClassifiedForRedaction is the self-discovering,
// fail-closed guard (#8): every TOTP event whose payload struct carries a
// secret-bearing field (secret_encrypted / backup_codes_hash) MUST have a
// matching redaction-schema path. The secret detection is reflective, so
// adding such a field to a TOTP payload without updating the schema fails
// here; the All()-enumeration guard fails if a new TOTP eventtype isn't
// classified in this test at all.
func TestEveryTOTPEventClassifiedForRedaction(t *testing.T) {
	secretTags := map[string]bool{"secret_encrypted": true, "backup_codes_hash": true}

	// Every eventtypes TOTP constant must appear here (nil = no secret
	// payload). A new TOTP event trips the All() guard below until added.
	payloadFor := map[eventtypes.EventType]any{
		eventtypes.TOTPSetupInitiated:         payloads.TOTPSetupInitiated{},
		eventtypes.TOTPBackupCodesRegenerated: payloads.TOTPBackupCodesRegenerated{},
		eventtypes.TOTPVerified:               nil,
		eventtypes.TOTPDisabled:               nil,
		eventtypes.TOTPBackupCodeUsed:         nil,
	}

	totpEvents := 0
	for _, et := range eventtypes.All() {
		if !strings.HasPrefix(string(et), "TOTP") {
			continue
		}
		totpEvents++
		if _, ok := payloadFor[et]; !ok {
			t.Errorf("TOTP event %q is not classified in this test — add it to payloadFor and decide redaction", et)
		}
	}
	if totpEvents == 0 {
		t.Fatal("found no TOTP events to classify — eventtypes enumeration broke")
	}

	totpSchemas := eventRedactionSchemas["totp"]
	for et, payload := range payloadFor {
		if payload == nil {
			continue
		}
		rt := reflect.TypeOf(payload)
		for i := 0; i < rt.NumField(); i++ {
			tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			if !secretTags[tag] {
				continue
			}
			schema, ok := totpSchemas[string(et)]
			if !ok {
				t.Errorf("TOTP event %q carries secret field %q but has no redaction schema", et, tag)
				continue
			}
			covered := false
			for _, p := range schema.paths {
				if p == tag {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("TOTP event %q redaction schema does not cover secret field %q", et, tag)
			}
		}
	}
}
