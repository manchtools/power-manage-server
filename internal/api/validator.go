package api

import (
	"connectrpc.com/connect"
	"github.com/go-playground/validator/v10"

	sdkvalidate "github.com/manchtools/power-manage/sdk/go/validate"
)

// validate is the shared validator instance with ULID custom rule.
var validate *validator.Validate

func init() {
	validate = sdkvalidate.NewValidator()
}

// Validate validates a struct using the go-playground validator.
// It returns a connect error with CodeInvalidArgument if validation fails.
func Validate(v any) error {
	msg, ok := sdkvalidate.Struct(validate, v)
	if !ok {
		return apiError(ErrValidationFailed, connect.CodeInvalidArgument, msg)
	}
	return nil
}
