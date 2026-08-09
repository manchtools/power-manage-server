package authoring

import (
	"errors"
	"strings"
	"testing"

	pmv1 "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// TestValidateActionSafetyRequiresSignedAgentUpdateManifest pins fail-closed source validation.
func TestValidateActionSafetyRequiresSignedAgentUpdateManifest(t *testing.T) {
	t.Parallel()
	validBinaryURL := "https://releases.example/power-manage-agent-linux-amd64"
	validChecksumURL := "https://releases.example/SHA256SUMS"

	tests := []struct {
		name string
		arch *pmv1.AgentUpdateArch
		ok   bool
	}{
		{name: "valid", arch: &pmv1.AgentUpdateArch{BinaryUrl: validBinaryURL, ChecksumUrl: validChecksumURL}, ok: true},
		{name: "missing checksum URL", arch: &pmv1.AgentUpdateArch{BinaryUrl: validBinaryURL}},
		{name: "non-HTTPS checksum URL", arch: &pmv1.AgentUpdateArch{BinaryUrl: validBinaryURL, ChecksumUrl: "http://releases.example/SHA256SUMS"}},
		{name: "hostless binary URL", arch: &pmv1.AgentUpdateArch{BinaryUrl: "https://", ChecksumUrl: validChecksumURL}},
		{name: "hostless checksum URL", arch: &pmv1.AgentUpdateArch{BinaryUrl: validBinaryURL, ChecksumUrl: "https://"}},
	}

	// Field 3 was the disposable pre-alpha expected_sha256 bypass. Old binary
	// protobuf input must not make an update valid after that field is removed.
	legacyWire := protowire.AppendTag(nil, 1, protowire.BytesType)
	legacyWire = protowire.AppendString(legacyWire, validBinaryURL)
	legacyWire = protowire.AppendTag(legacyWire, 3, protowire.BytesType)
	legacyWire = protowire.AppendString(legacyWire, strings.Repeat("a", 64))
	legacyArch := &pmv1.AgentUpdateArch{}
	if err := proto.Unmarshal(legacyWire, legacyArch); err != nil {
		t.Fatalf("unmarshal legacy agent-update field: %v", err)
	}
	tests = append(tests, struct {
		name string
		arch *pmv1.AgentUpdateArch
		ok   bool
	}{name: "removed expected SHA field", arch: legacyArch})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateActionSafety(&pmv1.AgentUpdateParams{Amd64: tc.arch})
			if tc.ok && err != nil {
				t.Fatalf("valid signed update source rejected: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsafe update error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
