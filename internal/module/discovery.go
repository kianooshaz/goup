package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/kianooshaz/goup/internal/runner"
)

// Discoverer discovers Go module dependencies and their available updates.
type Discoverer struct {
	runner  runner.CommandRunner
	workDir string
}

// NewDiscoverer creates a new Discoverer that runs Go commands in workDir.
func NewDiscoverer(runner runner.CommandRunner, workDir string) *Discoverer {
	return &Discoverer{
		runner:  runner,
		workDir: workDir,
	}
}

// Discover fetches module information using "go list -m -u -json all" and
// returns Dependency objects for modules that have available updates.
func (d *Discoverer) Discover(ctx context.Context, includeIndirect bool) ([]Dependency, error) {
	raw, err := d.runGoList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Go dependencies: %w", err)
	}

	modules, err := parseGoListOutput(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse module information: %w", err)
	}

	deps := convertToDependencies(modules, includeIndirect)
	SortDependencies(deps)
	return deps, nil
}

// runGoList executes "go list -m -u -json all" in the working directory.
func (d *Discoverer) runGoList(ctx context.Context) ([]byte, error) {
	out, err := d.runner.Run(ctx, "go", "-C", d.workDir, "list", "-m", "-u", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("go list -m -u failed:\n  %w", err)
	}
	return out, nil
}

// parseGoListOutput decodes the JSON-lines output from "go list -m -json all".
// Each line is an independent JSON object.
func parseGoListOutput(data []byte) ([]GoListModule, error) {
	var modules []GoListModule
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var m GoListModule
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("invalid module JSON: %w", err)
		}
		modules = append(modules, m)
	}
	return modules, nil
}

// convertToDependencies transforms raw GoListModule entries into Dependency
// objects, filtering out the main module and modules without updates.
func convertToDependencies(modules []GoListModule, includeIndirect bool) []Dependency {
	var deps []Dependency
	for _, m := range modules {
		// Skip the main module itself.
		if m.Main {
			continue
		}
		// Skip modules with no available update.
		if m.Update == nil {
			continue
		}
		// Skip indirect dependencies unless requested.
		if m.Indirect && !includeIndirect {
			continue
		}

		dep := Dependency{
			Path:           m.Path,
			CurrentVersion: m.Version,
			LatestVersion:  m.Update.Version,
			Indirect:       m.Indirect,
			UpdateType:     ClassifyUpdate(m.Version, m.Update.Version),
		}
		deps = append(deps, dep)
	}
	return deps
}
