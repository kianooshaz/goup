package module

import (
	"fmt"
	"sort"
)

// UpdateType classifies the kind of version update available.
type UpdateType int

const (
	UpdateUnknown UpdateType = iota
	UpdatePatch
	UpdateMinor
	UpdateMajor
)

func (u UpdateType) String() string {
	switch u {
	case UpdatePatch:
		return "patch"
	case UpdateMinor:
		return "minor"
	case UpdateMajor:
		return "major"
	default:
		return "unknown"
	}
}

// Dependency represents a single Go module dependency with version information.
type Dependency struct {
	Path           string
	CurrentVersion string
	LatestVersion  string
	Indirect       bool
	UpdateType     UpdateType
}

// ByDirectThenPath implements deterministic sorting:
//  1. Direct dependencies first, indirect second.
//  2. Alphabetically by module path within each group.
type ByDirectThenPath []Dependency

func (s ByDirectThenPath) Len() int { return len(s) }
func (s ByDirectThenPath) Less(i, j int) bool {
	if s[i].Indirect != s[j].Indirect {
		return !s[i].Indirect // direct (false) before indirect (true)
	}
	return s[i].Path < s[j].Path
}
func (s ByDirectThenPath) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// SortDependencies sorts dependencies in-place.
func SortDependencies(deps []Dependency) {
	sort.Sort(ByDirectThenPath(deps))
}

// Summary provides a human-readable description of the version change.
func (d Dependency) Summary() string {
	return fmt.Sprintf("%s %s → %s", d.Path, d.CurrentVersion, d.LatestVersion)
}

// GoListModule mirrors the JSON shape of "go list -m -json" output.
// Only the fields we use are included.
type GoListModule struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Main     bool   `json:"main"`
	Update   *struct {
		Path    string `json:"path"`
		Version string `json:"version"`
	} `json:"update"`
}
