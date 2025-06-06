package agent

import "testing"

func TestBuildExecutionCommand(t *testing.T) {
	tests := []struct {
		exec string
		want string
	}{
		{"", "/tmp/binary"},
		{"python", "python /tmp/binary"},
	}

	for _, tt := range tests {
		got := buildExecutionCommand(tt.exec)
		if got != tt.want {
			t.Errorf("buildExecutionCommand(%q) = %q, want %q", tt.exec, got, tt.want)
		}
	}
}
