package api

import (
	"context"
	"reflect"
	"strings"
	"testing"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

const validSha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex
const validURL = "https://example.com/agent"

func archOK() *pm.AgentUpdateArch {
	return &pm.AgentUpdateArch{
		BinaryUrl:      validURL,
		ChecksumUrl:    validURL + ".sha256",
		ExpectedSha256: validSha,
	}
}

// WS7 #1: every set arch entry MUST carry a 64-char lowercase-hex
// expected_sha256, so the hash that gates the self-update swap is inside
// the CA-signed payload. Driven through the REAL validateParamsMsg
// dispatch (the shared Create/Update/inline boundary), proving the rule
// runs at the action boundary, not just on the bare struct.
func TestValidateAgentUpdateParams_ExpectedSha256(t *testing.T) {
	ctx := context.Background()

	t.Run("correct accepted", func(t *testing.T) {
		err := validateParamsMsg(ctx, &pm.AgentUpdateParams{Amd64: archOK()})
		if err != nil {
			t.Fatalf("valid agent-update params rejected: %v", err)
		}
	})

	// "wrong" sourced from intent (sha256 is 64 lowercase-hex chars), not
	// from the validation tag.
	bad := map[string]string{
		"absent":    "",
		"too short": strings.Repeat("a", 63),
		"too long":  strings.Repeat("a", 65),
		"uppercase": strings.ToUpper(validSha),
		"non-hex":   strings.Repeat("g", 64),
	}
	for name, sha := range bad {
		t.Run("rejects "+name+" expected_sha256", func(t *testing.T) {
			arch := archOK()
			arch.ExpectedSha256 = sha
			if err := validateParamsMsg(ctx, &pm.AgentUpdateParams{Amd64: arch}); err == nil {
				t.Errorf("expected_sha256=%q must be rejected", sha)
			}
		})
	}

	t.Run("http binary_url still rejected", func(t *testing.T) {
		arch := archOK()
		arch.BinaryUrl = "http://example.com/agent"
		if err := validateParamsMsg(ctx, &pm.AgentUpdateParams{Amd64: arch}); err == nil {
			t.Error("http binary_url must be rejected")
		}
	})

	t.Run("http checksum_url still rejected", func(t *testing.T) {
		arch := archOK()
		arch.ChecksumUrl = "http://example.com/agent.sha256"
		if err := validateParamsMsg(ctx, &pm.AgentUpdateParams{Amd64: arch}); err == nil {
			t.Error("http checksum_url must be rejected")
		}
	})
}

func TestValidateAgentUpdateParams_AtLeastOneArch(t *testing.T) {
	if err := validateParamsMsg(context.Background(), &pm.AgentUpdateParams{}); err == nil {
		t.Error("agent-update with no arch must be rejected")
	}
}

// WS7 #2: deb/rpm/appimage download-and-install actions (the shared
// AppInstallParams `app` oneof) must carry a mandatory 64-hex
// checksum_sha256 and an https url. Driven through validateParamsMsg.
func TestValidateAppInstallParams_ChecksumMandatoryAndHTTPS(t *testing.T) {
	ctx := context.Background()

	t.Run("correct accepted", func(t *testing.T) {
		err := validateParamsMsg(ctx, &pm.AppInstallParams{
			Url:            "https://example.com/app.deb",
			ChecksumSha256: validSha,
		})
		if err != nil {
			t.Fatalf("valid app-install params rejected: %v", err)
		}
	})

	cases := []struct {
		name string
		p    *pm.AppInstallParams
	}{
		{"absent checksum", &pm.AppInstallParams{Url: "https://example.com/app.deb"}},
		{"short checksum", &pm.AppInstallParams{Url: "https://example.com/app.deb", ChecksumSha256: strings.Repeat("a", 63)}},
		{"non-hex checksum", &pm.AppInstallParams{Url: "https://example.com/app.deb", ChecksumSha256: strings.Repeat("z", 64)}},
		{"http url", &pm.AppInstallParams{Url: "http://example.com/app.deb", ChecksumSha256: validSha}},
		{"absent url", &pm.AppInstallParams{ChecksumSha256: validSha}},
	}
	for _, tc := range cases {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			if err := validateParamsMsg(ctx, tc.p); err == nil {
				t.Errorf("%s must be rejected", tc.name)
			}
		})
	}
}

// WS7 #1/#2 against silent drift: every exported field of the
// download-authenticity param structs must carry a validate gotag, so a
// future field can't land without a rule. Self-discovering: fails if zero
// fields are found, or any exported field lacks a `validate` tag.
func TestActionParamFields_HaveValidationRule(t *testing.T) {
	for _, msg := range []any{pm.AgentUpdateArch{}, pm.AppInstallParams{}} {
		typ := reflect.TypeOf(msg)
		checked := 0
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue // unexported proto-internal field (state/sizeCache/unknownFields)
			}
			checked++
			if _, ok := f.Tag.Lookup("validate"); !ok {
				t.Errorf("%s.%s has no validate gotag", typ.Name(), f.Name)
			}
		}
		if checked == 0 {
			t.Errorf("%s: no exported fields discovered (reflection guard tripped)", typ.Name())
		}
	}
}
