package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/kianooshaz/goup/internal/runner"
)

// SkippedDependency records a module that could not be processed, with the
// reason. Skips are isolated: one module's failure never prevents other
// dependencies from being discovered.
type SkippedDependency struct {
	Path   string
	Reason error
}

// DiscoveryResult is the structured outcome of dependency discovery:
// the dependencies that have available updates, plus everything that
// had to be skipped. The presentation layer renders both; discovery
// never prints to the terminal itself.
type DiscoveryResult struct {
	Dependencies []Dependency
	Skipped      []SkippedDependency
}

// Discoverer discovers Go module dependencies and their available updates.
type Discoverer struct {
	runner  runner.CommandRunner
	workDir string
}

// NewDiscoverer creates a Discoverer that runs Go commands in workDir.
func NewDiscoverer(runner runner.CommandRunner, workDir string) *Discoverer {
	return &Discoverer{
		runner:  runner,
		workDir: workDir,
	}
}

// Discover fetches module information using "go list -m -u -e -json all"
// and returns a DiscoveryResult. The -e flag makes go report per-module
// load errors in the JSON output instead of failing the whole command, so
// broken modules are skipped individually while healthy ones still appear.
// A fatal error (go itself missing, context cancelled) is returned as the
// error; per-module problems land in Skipped.
func (d *Discoverer) Discover(ctx context.Context, includeIndirect bool) (*DiscoveryResult, error) {
	raw, err := d.runGoList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Go dependencies: %w", err)
	}

	modules, skipped := parseGoListOutput(raw)
	deps, skippedFromConvert := convertToDependencies(modules, includeIndirect)
	skipped = append(skipped, skippedFromConvert...)
	SortDependencies(deps)
	return &DiscoveryResult{
		Dependencies: deps,
		Skipped:      skipped,
	}, nil
}

// runGoList executes "go list -m -u -e -json all" in the working directory.
func (d *Discoverer) runGoList(ctx context.Context) ([]byte, error) {
	out, err := d.runner.Run(ctx, "go", "-C", d.workDir, "list", "-m", "-u", "-e", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("go list -m -u failed:\n  %w", err)
	}
	return out, nil
}

// parseGoListOutput decodes the JSON stream from "go list -m -json all".
// Each decoded object is an independent module record; a malformed record
// is recorded as a skip (reason: malformed) rather than aborting the
// remaining parse.
func parseGoListOutput(data []byte) ([]GoListModule, []SkippedDependency) {
	var modules []GoListModule
	var skipped []SkippedDependency
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var m GoListModule
		if err := dec.Decode(&m); err != nil {
			skipped = append(skipped, SkippedDependency{
				Path:   "(unknown module)",
				Reason: fmt.Errorf("malformed module information: %w", err),
			})
			// The stream is damaged past this point; keep what we have.
			break
		}
		modules = append(modules, m)
	}
	return modules, skipped
}

// convertToDependencies transforms raw GoListModule entries into Dependency
// objects. Modules that failed to load (Error set, reported because of the
// -e flag) become skip records; the main module and modules without
// updates are silently omitted — they are not failures.
func convertToDependencies(modules []GoListModule, includeIndirect bool) ([]Dependency, []SkippedDependency) {
	var deps []Dependency
	var skipped []SkippedDependency
	for _, m := range modules {
		if m.Main {
			continue
		}
		// A module that go could not load: skip it, keep going.
		if m.Error != nil {
			reason := fmt.Errorf("failed to load module information")
			if m.Error.Err != "" {
				reason = fmt.Errorf("%s", m.Error.Err)
			}
			skipped = append(skipped, SkippedDependency{
				Path:   m.Path,
				Reason: reason,
			})
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
	return deps, skipped
}
