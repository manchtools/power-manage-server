package enrollment

import (
	"fmt"
	"net/url"
)

// ValidateControlURL accepts only an absolute HTTPS agent-listener URL without
// embedded credentials or a fragment.
func ValidateControlURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse agent URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("agent URL must use https")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("agent URL must include a host")
	}
	if u.User != nil {
		return fmt.Errorf("agent URL must not contain credentials")
	}
	if u.Fragment != "" {
		return fmt.Errorf("agent URL must not contain a fragment")
	}
	return nil
}
