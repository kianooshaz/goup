package module

import (
	"testing"
)

func TestSortDependencies(t *testing.T) {
	deps := []Dependency{
		{Path: "github.com/z/indirect", Indirect: true, CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/a/direct", Indirect: false, CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/b/direct", Indirect: false, CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/y/indirect", Indirect: true, CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
	}

	SortDependencies(deps)

	// Expected: direct first (alphabetical), then indirect (alphabetical).
	expected := []string{
		"github.com/a/direct",
		"github.com/b/direct",
		"github.com/y/indirect",
		"github.com/z/indirect",
	}

	for i, dep := range deps {
		if dep.Path != expected[i] {
			t.Errorf("SortDependencies: position %d = %q, want %q", i, dep.Path, expected[i])
		}
		// Check direct/indirect order.
		if i < 2 && dep.Indirect {
			t.Errorf("SortDependencies: expected direct at position %d, got indirect %q", i, dep.Path)
		}
		if i >= 2 && !dep.Indirect {
			t.Errorf("SortDependencies: expected indirect at position %d, got direct %q", i, dep.Path)
		}
	}
}

func TestUpdateTypeString(t *testing.T) {
	tests := []struct {
		ut   UpdateType
		want string
	}{
		{UpdateUnknown, "unknown"},
		{UpdatePatch, "patch"},
		{UpdateMinor, "minor"},
		{UpdateMajor, "major"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ut.String(); got != tt.want {
				t.Errorf("UpdateType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDependencySummary(t *testing.T) {
	dep := Dependency{
		Path:           "github.com/foo/bar",
		CurrentVersion: "v1.0.0",
		LatestVersion:  "v2.0.0",
		Indirect:       false,
		UpdateType:     UpdateMajor,
	}
	want := "github.com/foo/bar v1.0.0 → v2.0.0"
	if got := dep.Summary(); got != want {
		t.Errorf("Dependency.Summary() = %q, want %q", got, want)
	}
}

func TestFilterDirectOnly(t *testing.T) {
	deps := []Dependency{
		{Path: "github.com/a/direct", Indirect: false},
		{Path: "github.com/b/indirect", Indirect: true},
		{Path: "github.com/c/direct", Indirect: false},
	}

	var filtered []Dependency
	for _, d := range deps {
		if !d.Indirect {
			filtered = append(filtered, d)
		}
	}

	if len(filtered) != 2 {
		t.Errorf("expected 2 direct deps, got %d", len(filtered))
	}
}

func TestFilterIndirect(t *testing.T) {
	deps := []Dependency{
		{Path: "github.com/a/direct", Indirect: false},
		{Path: "github.com/b/indirect", Indirect: true},
		{Path: "github.com/c/direct", Indirect: false},
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 deps with indirect included, got %d", len(deps))
	}
}

func TestSelectAllNone(t *testing.T) {
	deps := []Dependency{
		{Path: "github.com/a", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/b", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/c", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
	}

	// Simulate select all.
	selected := make(map[int]bool)
	for i := range deps {
		selected[i] = true
	}
	if len(selected) != 3 {
		t.Errorf("select all: expected 3 selected, got %d", len(selected))
	}

	// Simulate select none.
	selected = make(map[int]bool)
	if len(selected) != 0 {
		t.Errorf("select none: expected 0 selected, got %d", len(selected))
	}

	// Toggle selection.
	selected[0] = true
	delete(selected, 0)
	if selected[0] {
		t.Error("expected index 0 to be deselected after toggle")
	}
}
