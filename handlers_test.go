package main

import (
	"testing"

	"github.com/brody192/locomotive/internal/config"
)

func TestClassifySeverityDropsUnmatchedMessages(t *testing.T) {
	t.Parallel()

	filter, err := NewFilterSettings(config.SeverityInfo, nil, nil, nil, nil, []string{`panic: runtime error`}, nil)
	if err != nil {
		t.Fatalf("NewFilterSettings() error = %v", err)
	}

	tests := []string{
		"Starting Container",
		"panic: runtime error: invalid memory address",
		"received ERR later in the message",
	}

	for _, msg := range tests {
		msg := msg
		t.Run(msg, func(t *testing.T) {
			t.Parallel()

			_, ok := classifySeverity(msg, filter)
			if ok {
				t.Fatal("classifySeverity() classified message without leading severity marker")
			}
		})
	}
}

func TestClassifySeverityRequiresExplicitErrorSignal(t *testing.T) {
	t.Parallel()

	filter, err := NewFilterSettings(
		config.SeverityInfo,
		nil,
		nil,
		[]string{`indexer poisoned`},
		nil,
		[]string{`panic: runtime error`},
		nil,
	)
	if err != nil {
		t.Fatalf("NewFilterSettings() error = %v", err)
	}

	tests := []struct {
		name string
		msg  string
		want config.SeverityLevel
	}{
		{
			name: "warn whitelist overrides ERR token",
			msg:  "2026-06-11T01:08:13.117Z ERR indexer poisoned: stream_receive_failed",
			want: config.SeverityWarn,
		},
		{
			name: "error keyword",
			msg:  "2026-06-11T01:08:13.117Z ERROR failed to apply event",
			want: config.SeverityError,
		},
		{
			name: "fatal keyword",
			msg:  "2026-06-11T01:08:13.117Z FATAL process exited",
			want: config.SeverityFatal,
		},
		{
			name: "leading warning keyword",
			msg:  "WRN failed to update asset candles",
			want: config.SeverityWarn,
		},
		{
			name: "error whitelist with leading severity",
			msg:  "ERR panic: runtime error: invalid memory address",
			want: config.SeverityError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := classifySeverity(tt.msg, filter)
			if !ok {
				t.Fatalf("classifySeverity() did not classify %q", tt.msg)
			}
			if got != tt.want {
				t.Fatalf("classifySeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}
