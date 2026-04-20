package handler

import "testing"

// Locks down the rc6 close-code matrix: which agent error messages
// are mapped to StatusPolicyViolation (1008, no retry) vs left to
// the default StatusInternalError (1011, retry may help). The helper
// is a stopgap for a proper structured refusal reason on
// TerminalStateChange — see terminal_bridge.go.
func TestIsTerminalPolicyRefusal(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{
			name: "tty disabled — classic refusal",
			msg:  "terminal sessions are disabled on this device",
			want: true,
		},
		{
			name: "tty disabled — with trailing detail",
			msg:  "terminal sessions are disabled on this device (cause: store unreadable)",
			want: true,
		},
		{
			name: "locked pm-tty account",
			msg:  `tty user "pm-tty-alice" is disabled`,
			want: true,
		},
		{
			name: "pty allocation EPERM — transient, must be retryable",
			msg:  "allocate pty: terminal: start pty: fork/exec /bin/bash: operation not permitted",
			want: false,
		},
		{
			name: "tty user not provisioned — ambiguous, conservatively retryable",
			msg:  `tty user "pm-tty-bob" not provisioned: exit status 6`,
			want: false,
		},
		{
			name: "generic unknown — retryable by default",
			msg:  "unexpected whatever",
			want: false,
		},
		{
			name: "empty — retryable",
			msg:  "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTerminalPolicyRefusal(tt.msg)
			if got != tt.want {
				t.Errorf("isTerminalPolicyRefusal(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}
