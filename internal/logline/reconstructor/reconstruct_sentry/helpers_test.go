package reconstruct_sentry

import "testing"

func TestNormalizeLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "warn", want: "warning"},
		{in: "WARN", want: "warning"},
		{in: "warning", want: "warning"},
		{in: "err", want: "error"},
		{in: "error", want: "error"},
		{in: "info", want: "info"},
		{in: "debug", want: "debug"},
		{in: "fatal", want: "fatal"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			if got := normalizeLevel(tt.in); got != tt.want {
				t.Fatalf("normalizeLevel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
