package crypto

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Reflection walker over typed event payloads: seals/opens exactly the
// fields tagged pii:"true" (string or *string), addressed by their
// json wire name — the same name the field is AAD-bound to, so a
// sealed value cannot be relocated to a different field. The PII set
// is code-declared on the payload structs and self-discovered here;
// no hand-maintained list exists anywhere (spec 19 AC 3).

// piiTag is the struct tag marking a personal-data field.
const piiTag = "pii"

// jsonName extracts the wire name from a field's json tag ("email"
// from `json:"email,omitempty"`); falls back to the Go field name.
func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return f.Name
	}
	if i := strings.Index(tag, ","); i >= 0 {
		return tag[:i]
	}
	return tag
}

// PIIFieldNames returns the json wire names of every pii:"true" field
// on the payload's struct type, in declaration order. Used by the
// completeness guard and by callers deciding whether a payload needs a
// DEK at all.
func PIIFieldNames(payload any) []string {
	t := reflect.TypeOf(payload)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	var names []string
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get(piiTag) == "true" {
			names = append(names, jsonName(t.Field(i)))
		}
	}
	return names
}

// SealPayloadPII returns a COPY of the payload with every pii-tagged
// field sealed under the DEK (field-bound AAD). The input is never
// mutated. Payloads without tags are returned unchanged. Only string
// and *string fields may carry the tag — any other tagged kind is a
// programming error surfaced loudly.
func SealPayloadPII(dek *DEK, payload any) (any, error) {
	return walkPII(payload, dek.SealField)
}

// OpenPayloadPII opens every pii-tagged field IN PLACE on the pointed-
// to payload. Values without the pii prefix pass through (pre-envelope
// plaintext events). payload must be a non-nil pointer to a struct.
func OpenPayloadPII(dek *DEK, payload any) error {
	v := reflect.ValueOf(payload)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errors.New("crypto: OpenPayloadPII needs a non-nil pointer to a payload struct")
	}
	opened, err := walkPII(v.Elem().Interface(), dek.OpenField)
	if err != nil {
		return err
	}
	v.Elem().Set(reflect.ValueOf(opened))
	return nil
}

// walkPII applies fn to every pii-tagged string/*string field of a
// copy of the payload and returns the modified copy.
func walkPII(payload any, fn func(value, field string) (string, error)) (any, error) {
	src := reflect.ValueOf(payload)
	if src.Kind() != reflect.Struct {
		return nil, fmt.Errorf("crypto: PII payload must be a struct, got %T", payload)
	}
	t := src.Type()

	// Copy first; mutate only the copy.
	dst := reflect.New(t).Elem()
	dst.Set(src)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Tag.Get(piiTag) != "true" {
			continue
		}
		field := jsonName(f)
		fv := dst.Field(i)
		switch {
		case fv.Kind() == reflect.String:
			out, err := fn(fv.String(), field)
			if err != nil {
				return nil, fmt.Errorf("PII field %s: %w", field, err)
			}
			fv.SetString(out)
		case fv.Kind() == reflect.Pointer && f.Type.Elem().Kind() == reflect.String:
			if fv.IsNil() {
				continue
			}
			out, err := fn(fv.Elem().String(), field)
			if err != nil {
				return nil, fmt.Errorf("PII field %s: %w", field, err)
			}
			np := reflect.New(f.Type.Elem())
			np.Elem().SetString(out)
			fv.Set(np)
		default:
			return nil, fmt.Errorf("crypto: pii:\"true\" on unsupported field kind %s (%s.%s) — only string and *string carry PII", f.Type.Kind(), t.Name(), f.Name)
		}
	}
	return dst.Interface(), nil
}
