// Package sqlitetype contains the small database/sql adapters needed for
// SQLite values that deliberately retain their JSON shape in Go.
package sqlitetype

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON stores validated JSON text while retaining []byte ergonomics at call
// sites. SQLite validates the same value again with schema CHECK constraints.
type JSON []byte

// Scan implements sql.Scanner.
func (j *JSON) Scan(src any) error {
	if j == nil {
		return errors.New("sqlite JSON scan requires a destination")
	}
	if src == nil {
		*j = nil
		return nil
	}
	var value []byte
	switch src := src.(type) {
	case string:
		value = []byte(src)
	case []byte:
		value = append([]byte(nil), src...)
	default:
		return fmt.Errorf("sqlite JSON cannot scan %T", src)
	}
	if !json.Valid(value) {
		return errors.New("sqlite JSON contains invalid JSON")
	}
	*j = value
	return nil
}

// Value implements driver.Valuer.
func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	if !json.Valid(j) {
		return nil, errors.New("sqlite JSON contains invalid JSON")
	}
	return string(j), nil
}

// StringList stores a JSON array of strings as a native Go slice.
type StringList []string

// Scan implements sql.Scanner.
func (s *StringList) Scan(src any) error {
	if s == nil {
		return errors.New("sqlite string-list scan requires a destination")
	}
	var raw []byte
	switch src := src.(type) {
	case string:
		raw = []byte(src)
	case []byte:
		raw = src
	case nil:
		*s = nil
		return nil
	default:
		return fmt.Errorf("sqlite string list cannot scan %T", src)
	}
	var value []string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("sqlite string list: %w", err)
	}
	if value == nil {
		value = []string{}
	}
	*s = value
	return nil
}

// Value implements driver.Valuer.
func (s StringList) Value() (driver.Value, error) {
	// Every StringList-backed schema column is NOT NULL. A nil Go slice is
	// therefore the empty JSON array, while SQL NULL remains unrepresentable.
	if s == nil {
		s = StringList{}
	}
	value, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("sqlite string list: %w", err)
	}
	return string(value), nil
}
