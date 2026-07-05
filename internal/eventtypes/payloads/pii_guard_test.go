package payloads_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/eventtypes/payloads"
)

// Spec 19 AC 3 — the PII completeness guard. The PII set is
// code-declared (pii:"true" on the payload structs) and SELF-DISCOVERED
// here by AST scan, never hardcoded: every tagged field must (a)
// round-trip through a DEK seal/open, and (b) resolve a subject user —
// either the stream id (user-stream events) or a payload field carrying
// the owning user's ULID. A tagged field failing either fails this
// test; an entry here without a tag in the source fails as stale.

// piiSubjectStream marks payloads that ride the "user" stream: the
// subject is the event's stream_id, no payload field needed.
const piiSubjectStream = "stream"

// piiRegistry: one entry per PII-bearing payload struct. fixture must
// populate EVERY tagged field (the round-trip proves each seals);
// subject names the json field carrying the owner's ULID, or
// piiSubjectStream for user-stream payloads.
var piiRegistry = map[string]struct {
	fixture any
	subject string
}{
	"UserCreatedWithRoles": {
		fixture: payloads.UserCreatedWithRoles{
			Email:             ptr("a@b.com"),
			DisplayName:       ptr("Alice"),
			GivenName:         ptr("Alice"),
			FamilyName:        ptr("Example"),
			PreferredUsername: ptr("alice"),
			Picture:           ptr("https://example.com/a.png"),
			LinuxUsername:     ptr("alice"),
		},
		subject: piiSubjectStream,
	},
	"UserProfileUpdated": {
		fixture: payloads.UserProfileUpdated{
			DisplayName:       ptr("Alice"),
			GivenName:         ptr("Alice"),
			FamilyName:        ptr("Example"),
			PreferredUsername: ptr("alice"),
			Picture:           ptr("https://example.com/a.png"),
		},
		subject: piiSubjectStream,
	},
	"UserEmailChanged": {
		fixture: payloads.UserEmailChanged{Email: ptr("a@b.com")},
		subject: piiSubjectStream,
	},
	"UserLinuxUsernameChanged": {
		fixture: payloads.UserLinuxUsernameChanged{LinuxUsername: ptr("alice")},
		subject: piiSubjectStream,
	},
	"IdentityLinked": {
		fixture: payloads.IdentityLinked{
			UserID:        "01JUSERAAAAAAAAAAAAAAAAAAA",
			ProviderID:    "01JPROVAAAAAAAAAAAAAAAAAAA",
			ExternalID:    "ext-1",
			ExternalEmail: "a@idp.example",
			ExternalName:  "Alice Example",
		},
		subject: "user_id",
	},
	"IdentityLinkLoginUpdated": {
		fixture: payloads.IdentityLinkLoginUpdated{
			UserID:        "01JUSERAAAAAAAAAAAAAAAAAAA",
			ProviderID:    "01JPROVAAAAAAAAAAAAAAAAAAA",
			ExternalID:    "ext-1",
			ExternalEmail: "a@idp.example",
			ExternalName:  "Alice Example",
		},
		subject: "user_id",
	},
	"TerminalAdminMembershipRevoked": {
		fixture: payloads.TerminalAdminMembershipRevoked{
			UserID:        "01JUSERAAAAAAAAAAAAAAAAAAA",
			LinuxUsername: "alice",
			ActionID:      "01JACTAAAAAAAAAAAAAAAAAAAA",
			AccessLevel:   "ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED",
		},
		subject: "user_id",
	},
}

// discoverTaggedStructs AST-scans this package's source for structs
// carrying pii:"true" fields → structName → tagged json field names.
func discoverTaggedStructs(t *testing.T) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	out := map[string][]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, entry.Name(), nil, 0)
		require.NoError(t, err)
		{
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, f := range st.Fields.List {
					if f.Tag == nil {
						continue
					}
					raw, err := strconv.Unquote(f.Tag.Value)
					require.NoError(t, err)
					tag := reflect.StructTag(raw)
					if tag.Get("pii") != "true" {
						continue
					}
					jsonTag := tag.Get("json")
					name := jsonTag
					if i := strings.Index(jsonTag, ","); i >= 0 {
						name = jsonTag[:i]
					}
					require.NotEmpty(t, name, "%s: pii field without a json name", ts.Name.Name)
					out[ts.Name.Name] = append(out[ts.Name.Name], name)
				}
				return true
			})
		}
	}
	return out
}

func TestPIITagGuard_EveryTaggedFieldRoundTripsAndResolvesASubject(t *testing.T) {
	discovered := discoverTaggedStructs(t)

	// Matches-zero: the scan must see the known-tagged surface or the
	// detector is dead and the whole guard passes vacuously.
	total := 0
	for _, fields := range discovered {
		total += len(fields)
	}
	require.GreaterOrEqual(t, total, 10,
		"AST scan found only %d pii-tagged fields — detector mis-scoped", total)

	// Completeness in both directions.
	for structName, fields := range discovered {
		entry, ok := piiRegistry[structName]
		require.Truef(t, ok,
			"%s carries pii:\"true\" fields %v but has no piiRegistry entry — add a fixture and its subject resolution", structName, fields)

		// (a) The reflection walker sees exactly the tagged set.
		walkerFields := crypto.PIIFieldNames(entry.fixture)
		assert.ElementsMatchf(t, fields, walkerFields,
			"%s: AST-discovered PII set and the runtime walker disagree", structName)

		// (a) DEK round-trip: every tagged field seals to pii:v1
		// ciphertext and opens back to the original.
		dek := guardDEK(t)
		sealed, err := crypto.SealPayloadPII(dek, entry.fixture)
		require.NoErrorf(t, err, "%s: seal", structName)

		var sealedMap map[string]any
		b, err := json.Marshal(sealed)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(b, &sealedMap))
		for _, f := range fields {
			v, present := sealedMap[f]
			require.Truef(t, present,
				"%s.%s: fixture must populate every tagged field (empty fields prove nothing)", structName, f)
			s, _ := v.(string)
			assert.Truef(t, strings.HasPrefix(s, "pii:v1:"),
				"%s.%s did not seal — got %q", structName, f, s)
		}

		sealedCopy := sealed
		require.NoError(t, openInPlace(dek, &sealedCopy))
		assert.Equalf(t, entry.fixture, sealedCopy, "%s: open must restore the original", structName)

		// (b) Subject resolution: user-stream payloads resolve via
		// stream_id; everything else must carry a populated owner field.
		if entry.subject != piiSubjectStream {
			owner, present := fieldByJSONName(t, entry.fixture, entry.subject)
			require.Truef(t, present,
				"%s: registry names subject field %q but the struct has no such field", structName, entry.subject)
			assert.NotEmptyf(t, owner,
				"%s: subject field %q must be populated in the fixture — an off-stream PII payload without an owner is unshreddable", structName, entry.subject)
		}
	}
	for structName := range piiRegistry {
		_, ok := discovered[structName]
		assert.Truef(t, ok,
			"piiRegistry entry %q matches no pii-tagged struct in the source — stale entry, delete it", structName)
	}
}

// guardDEK mints a throwaway DEK for round-trip checks.
func guardDEK(t *testing.T) *crypto.DEK {
	t.Helper()
	kek, err := crypto.NewEncryptor(strings.Repeat("ab", 32))
	require.NoError(t, err)
	wrapped, err := crypto.GenerateWrappedDEK(kek, "01JGUARDUSERAAAAAAAAAAAAAA")
	require.NoError(t, err)
	dek, err := crypto.UnwrapDEK(kek, "01JGUARDUSERAAAAAAAAAAAAAA", wrapped)
	require.NoError(t, err)
	return dek
}

// openInPlace adapts OpenPayloadPII (pointer-to-struct) to an `any`
// holding a struct value.
func openInPlace(dek *crypto.DEK, payload *any) error {
	v := reflect.New(reflect.TypeOf(*payload))
	v.Elem().Set(reflect.ValueOf(*payload))
	if err := crypto.OpenPayloadPII(dek, v.Interface()); err != nil {
		return err
	}
	*payload = v.Elem().Interface()
	return nil
}

// fieldByJSONName returns the string value of the struct field whose
// json wire name matches, and whether such a field exists.
func fieldByJSONName(t *testing.T, payload any, jsonField string) (string, bool) {
	t.Helper()
	v := reflect.ValueOf(payload)
	tt := v.Type()
	for i := 0; i < tt.NumField(); i++ {
		tag := tt.Field(i).Tag.Get("json")
		name := tag
		if idx := strings.Index(tag, ","); idx >= 0 {
			name = tag[:idx]
		}
		if name != jsonField {
			continue
		}
		f := v.Field(i)
		if f.Kind() == reflect.Pointer {
			if f.IsNil() {
				return "", true
			}
			f = f.Elem()
		}
		return f.String(), true
	}
	return "", false
}
