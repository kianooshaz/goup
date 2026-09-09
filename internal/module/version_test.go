package module

import (
	"testing"
)

func TestClassifyUpdate(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    UpdateType
	}{
		// Standard patch updates.
		{"patch update", "v1.0.0", "v1.0.1", UpdatePatch},
		{"patch update with v prefix", "v2.3.4", "v2.3.5", UpdatePatch},

		// Standard minor updates.
		{"minor update", "v1.0.0", "v1.1.0", UpdateMinor},
		{"minor update larger jump", "v1.0.0", "v1.5.0", UpdateMinor},

		// Standard major updates.
		{"major update", "v1.0.0", "v2.0.0", UpdateMajor},
		{"major update v2", "v1.9.0", "v3.0.0", UpdateMajor},

		// v0.x behavior.
		{"v0 minor update", "v0.1.0", "v0.2.0", UpdateMinor},
		{"v0 major to v1", "v0.5.0", "v1.0.0", UpdateMajor},

		// Pre-release handling.
		{"pre-release to stable patch", "v1.0.0-alpha", "v1.0.0", UpdatePatch},
		{"pre-release to stable minor", "v1.0.0-beta", "v1.1.0", UpdateMinor},
		{"pre-release to stable major", "v1.0.0-rc1", "v2.0.0", UpdateMajor},

		// Same version (should not normally appear, but defensive).
		{"same version", "v1.0.0", "v1.0.0", UpdateUnknown},

		// Current ahead of latest (should not normally appear).
		{"current ahead", "v2.0.0", "v1.0.0", UpdateUnknown},

		// Empty strings.
		{"empty current", "", "v1.0.0", UpdateUnknown},
		{"empty latest", "v1.0.0", "", UpdateUnknown},
		{"both empty", "", "", UpdateUnknown},

		// Pseudo-versions (like v0.0.0-20230101123456-abcdef123456).
		{"pseudo to release", "v0.0.0-20230101123456-abcdef123456", "v1.0.0", UpdateMajor},

		// No v prefix.
		{"no v prefix current", "1.0.0", "v2.0.0", UpdateMajor},
		{"no v prefix latest", "v1.0.0", "2.0.0", UpdateMajor},
		{"no v prefix both", "1.0.0", "1.1.0", UpdateMinor},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyUpdate(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("ClassifyUpdate(%q, %q) = %v, want %v",
					tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseVersionParts(t *testing.T) {
	tests := []struct {
		version   string
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{"v1.2.3", 1, 2, 3},
		{"v10.20.30", 10, 20, 30},
		{"1.2.3", 1, 2, 3},
		{"v1.2.3-alpha", 1, 2, 3},
		{"v1.2.3+build", 1, 2, 3},
		{"v1.2", 1, 2, -1},
		{"v1", 1, -1, -1},
		{"", -1, -1, -1},
		{"invalid", -1, -1, -1},
		{"v0.0.0", 0, 0, 0},
		{"v1.2.3.4", 1, 2, -1},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			major, minor, patch := parseVersionParts(tt.version)
			if major != tt.wantMajor || minor != tt.wantMinor || patch != tt.wantPatch {
				t.Errorf("parseVersionParts(%q) = (%d, %d, %d), want (%d, %d, %d)",
					tt.version, major, minor, patch, tt.wantMajor, tt.wantMinor, tt.wantPatch)
			}
		})
	}
}

func TestIsPseudoVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"v0.0.0-20230101123456-abcdef123456", true},
		{"v1.0.0", false},
		{"v1.2.3-pre", false},
		{"", false},
		{"v0.0.0-20230101123456-abcdef123456+incompatible", true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := isPseudoVersion(tt.version)
			if got != tt.want {
				t.Errorf("isPseudoVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestClassifyUpdate_EdgeCases(t *testing.T) {
	// Major version suffix in path is handled separately; here we just test
	// that the version comparison logic doesn't crash on unusual formats.
	tests := []struct {
		current string
		latest  string
		want    UpdateType
	}{
		{"v1.0.0", "v1.0.1", UpdatePatch},
		{"v1.0.0", "v1.1.0", UpdateMinor},
		{"v1.0.0", "v2.0.0", UpdateMajor},
		{"v0.0.0", "v0.1.0", UpdateMinor},
		{"v0.0.0", "v1.0.0", UpdateMajor},
		{"v1.0.0-alpha", "v1.0.0", UpdatePatch},
		{"v1.0.0-alpha", "v1.0.1", UpdatePatch},
		{"v1.0.0-alpha", "v1.1.0", UpdateMinor},
	}

	for _, tt := range tests {
		t.Run(tt.current+"->"+tt.latest, func(t *testing.T) {
			got := ClassifyUpdate(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("ClassifyUpdate(%q, %q) = %v, want %v",
					tt.current, tt.latest, got, tt.want)
			}
		})
	}
}
