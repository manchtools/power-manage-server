package search

import (
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// sanitizeSearchField must drop ASCII control characters and angle brackets and
// cap length, so an agent-reported value cannot bloat the index or smuggle
// markup into a UI that renders raw search fields. The hostile inputs are
// sourced from intent (NUL/newline/escape control bytes, <script> markup,
// over-long strings), not from the stripping rule itself.
func TestSanitizeSearchField(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"empty stays empty", "", 253, ""},
		{"plain hostname passes through", "web-01.example.com", 253, "web-01.example.com"},
		{"strips NUL/newline/tab/escape", "host\x00\n\t\x1bname", 253, "hostname"},
		{"strips DEL", "ab\x7fcd", 253, "abcd"},
		{"strips angle brackets (markup)", "<script>alert(1)</script>x", 253, "scriptalert(1)/scriptx"},
		{"preserves multibyte", "café-böx", 253, "café-böx"},
		{"caps length to maxRunes", strings.Repeat("a", 300), 10, strings.Repeat("a", 10)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeSearchField(tc.in, tc.max)
			if got != tc.want {
				t.Errorf("sanitizeSearchField(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
			if strings.ContainsAny(got, "<>") {
				t.Errorf("result %q still contains angle brackets", got)
			}
			for _, r := range got {
				if r < 0x20 || r == 0x7f {
					t.Errorf("result %q still contains a control char %#x", got, r)
				}
			}
		})
	}
}

// entityFields is the LIVE index-update path; it must sanitize every
// agent-reported device field exactly as Index.warmDevices does on the warm
// path (both call sanitizeSearchField). Pin that a hostile device record is
// bounded/stripped before it becomes the HSET payload.
func TestEntityFields_Device_SanitizesAgentControlledFields(t *testing.T) {
	data := &taskqueue.SearchEntityData{
		Hostname:     "<b>evil</b>\x00host\n",
		AgentVersion: "2026.2.0\x07",
		Labels:       "env=prod\x1b<x>",
		OSName:       "Ubuntu<script>",
		OSVersion:    "24.04\n",
		OSArch:       "x86_64\x00",
		Kernel:       strings.Repeat("k", maxOSField+50),
	}
	fields := entityFields(ScopeDevice, data)

	for _, key := range []string{"hostname", "agent_version", "labels", "os_name", "os_version", "os_arch", "kernel"} {
		v, ok := fields[key].(string)
		if !ok {
			t.Fatalf("field %q missing or not a string: %v", key, fields[key])
		}
		if strings.ContainsAny(v, "<>") {
			t.Errorf("field %q = %q still contains angle brackets", key, v)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				t.Errorf("field %q = %q still contains a control char %#x", key, v, r)
			}
		}
	}
	// Only the angle brackets and control chars are removed — the surrounding
	// text survives (we neutralize markup, we don't drop arbitrary letters).
	if got := fields["hostname"].(string); !strings.Contains(got, "evil") || !strings.Contains(got, "host") {
		t.Errorf("hostname = %q, want the non-markup text preserved", got)
	}
	if got := len([]rune(fields["kernel"].(string))); got > maxOSField {
		t.Errorf("kernel rune length = %d, want <= %d", got, maxOSField)
	}
}
