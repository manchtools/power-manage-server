package scim

import (
	"errors"
	"strings"
)

// Errors a malformed patch operation produces. They are fixed strings:
// an error message is the easiest accidental oracle in a request
// surface, so the offending value is never interpolated into one.
var (
	errPatchActiveValue   = errors.New("the active value must be a boolean")
	errPatchUserNameValue = errors.New("the userName value must be a non-empty string")
	errPatchEmailsValue   = errors.New("the emails value must be a non-empty array of email objects")
	errPatchNameValue     = errors.New("the name value must be an object")
	errPatchNoPathValue   = errors.New("a replace without a path requires an object value")
)

// applyUserPatchOp folds one replace operation into the assertion the
// whole request builds.
//
// An attribute this surface does not model is ignored rather than
// refused: a directory that also syncs, say, a phone number must not
// have its whole request fail because of an attribute Power Manage
// keeps no column for.
func applyUserPatchOp(a *subjectAssertion, op SCIMPatchOp) error {
	switch strings.ToLower(strings.TrimSpace(op.Path)) {
	case "active":
		active, err := patchBool(op.Value)
		if err != nil {
			return err
		}
		a.Active = &active

	case "username":
		value, ok := op.Value.(string)
		if !ok || value == "" {
			return errPatchUserNameValue
		}
		email := normalizeEmail(value)
		a.Email = &email

	case "emails":
		email, err := patchPrimaryEmail(op.Value)
		if err != nil {
			return err
		}
		a.Email = &email

	case "name":
		fields, ok := op.Value.(map[string]any)
		if !ok {
			return errPatchNameValue
		}
		// Partial by construction: only the keys the directory supplied
		// are asserted, so the others keep whatever they hold.
		if v, ok := fields["givenName"].(string); ok {
			a.GivenName = &v
		}
		if v, ok := fields["familyName"].(string); ok {
			a.FamilyName = &v
		}
		if v, ok := fields["formatted"].(string); ok {
			a.DisplayName = &v
		}

	case "name.givenname":
		v, ok := op.Value.(string)
		if !ok {
			return errPatchNameValue
		}
		a.GivenName = &v

	case "name.familyname":
		v, ok := op.Value.(string)
		if !ok {
			return errPatchNameValue
		}
		a.FamilyName = &v

	case "name.formatted":
		v, ok := op.Value.(string)
		if !ok {
			return errPatchNameValue
		}
		a.DisplayName = &v

	case "":
		// A replace with no path carries a map of attributes; each key
		// is the path of an implied operation.
		fields, ok := op.Value.(map[string]any)
		if !ok {
			return errPatchNoPathValue
		}
		for key, value := range fields {
			if err := applyUserPatchOp(a, SCIMPatchOp{
				Op:    SCIMPatchOpReplace,
				Path:  key,
				Value: value,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// patchBool reads the flag directories send either as a JSON boolean or
// as its string spelling. Anything else is refused rather than read as
// false, which would turn a malformed request into a deactivation.
func patchBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, errPatchActiveValue
}

// patchPrimaryEmail reads the address out of a SCIM emails value,
// preferring the entry the directory marked primary.
func patchPrimaryEmail(value any) (string, error) {
	entries, ok := value.([]any)
	if !ok || len(entries) == 0 {
		return "", errPatchEmailsValue
	}
	chosen := ""
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		address, ok := entry["value"].(string)
		if !ok || address == "" {
			continue
		}
		if primary, _ := entry["primary"].(bool); primary {
			return normalizeEmail(address), nil
		}
		if chosen == "" {
			chosen = address
		}
	}
	if chosen == "" {
		return "", errPatchEmailsValue
	}
	return normalizeEmail(chosen), nil
}
