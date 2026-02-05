package connection

import "errors"

var (
	// ErrAgentNotConnected is returned when trying to send to a disconnected agent.
	ErrAgentNotConnected = errors.New("agent not connected")
)
