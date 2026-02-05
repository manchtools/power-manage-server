package api

import (
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
)

// validate is the shared validator instance.
var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom ULID validator
	validate.RegisterValidation("ulid", validateULID)
}

// validateULID validates that a string is a valid ULID.
func validateULID(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true // Let 'required' handle empty values
	}
	_, err := ulid.Parse(value)
	return err == nil
}

// Validate validates a struct using the go-playground validator.
// It returns a connect error with CodeInvalidArgument if validation fails.
func Validate(v any) error {
	if err := validate.Struct(v); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			return connect.NewError(connect.CodeInvalidArgument, formatValidationErrors(validationErrors))
		}
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return nil
}

// formatValidationErrors formats validation errors into a human-readable error.
func formatValidationErrors(errs validator.ValidationErrors) error {
	var messages []string
	for _, e := range errs {
		messages = append(messages, formatFieldError(e))
	}
	return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
}

// formatFieldError formats a single field error into a human-readable message.
func formatFieldError(e validator.FieldError) string {
	field := toSnakeCase(e.Field())

	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "min":
		if e.Kind().String() == "string" {
			return fmt.Sprintf("%s must be at least %s characters", field, e.Param())
		}
		return fmt.Sprintf("%s must be at least %s", field, e.Param())
	case "max":
		if e.Kind().String() == "string" {
			return fmt.Sprintf("%s must be at most %s characters", field, e.Param())
		}
		return fmt.Sprintf("%s must be at most %s", field, e.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, e.Param())
	case "ulid":
		return fmt.Sprintf("%s must be a valid ULID", field)
	case "startswith":
		return fmt.Sprintf("%s must start with %s", field, e.Param())
	default:
		return fmt.Sprintf("%s failed validation: %s", field, e.Tag())
	}
}

// toSnakeCase converts a PascalCase or camelCase string to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			result.WriteRune(r + 32) // Convert to lowercase
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}
