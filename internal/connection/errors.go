package connection

import "errors"

var (
	// ErrAgentNotConnected is returned when trying to send to a disconnected agent.
	ErrAgentNotConnected = errors.New("agent not connected")

	// ErrSendTimeout is returned when a frame could not be written to the device
	// within SendTimeout. Distinct from ErrAgentNotConnected because the
	// connection was live when the write began: the device accepted the stream
	// and then stopped reading it. The connection is closed as a side effect, so
	// a caller that retries will get ErrAgentNotConnected.
	ErrSendTimeout = errors.New("timed out sending to agent")
)
