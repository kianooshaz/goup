package cli

import (
	"errors"
	"flag"
	"testing"

	"github.com/kianooshaz/goup/internal/tui"
)

// TestSecurityModeMapping pins the flag-to-mode mapping. A regression here
// is silent — the flag parses, the UI opens, and the filter just never
// applies — so it is asserted explicitly.
func TestSecurityModeMapping(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want tui.SecurityMode
	}{
		{"default", Config{}, tui.SecurityOn},
		{"--security", Config{Security: true}, tui.SecurityOnly},
		{"--no-security", Config{NoSecurity: true}, tui.SecurityOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securityMode(&tt.cfg); got != tt.want {
				t.Errorf("securityMode(%+v) = %v, want %v", tt.cfg, got, tt.want)
			}
		})
	}
}

func TestParseFlagsSecurityModes(t *testing.T) {
	cfg, err := parseFlags([]string{"--security"})
	if err != nil {
		t.Fatalf("--security should parse: %v", err)
	}
	if got := securityMode(cfg); got != tui.SecurityOnly {
		t.Errorf("--security produced mode %v, want SecurityOnly", got)
	}

	cfg, err = parseFlags([]string{"--no-security"})
	if err != nil {
		t.Fatalf("--no-security should parse: %v", err)
	}
	if got := securityMode(cfg); got != tui.SecurityOff {
		t.Errorf("--no-security produced mode %v, want SecurityOff", got)
	}
}

func TestParseFlagsRejectsConflictingSecurityFlags(t *testing.T) {
	_, err := parseFlags([]string{"--security", "--no-security"})
	if err == nil {
		t.Fatal("--security with --no-security must be rejected")
	}
}

func TestParseFlagsHelp(t *testing.T) {
	_, err := parseFlags([]string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("--help should return flag.ErrHelp, got %v", err)
	}
}
