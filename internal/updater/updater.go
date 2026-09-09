package updater

import (
	"context"
	"fmt"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/runner"
)

// Result describes the outcome of upgrading a single dependency.
type Result struct {
	Path       string
	OldVersion string
	NewVersion string
	Success    bool
	Error      string
}

// ProgressUpdate is sent through a channel during an upgrade batch.
type ProgressUpdate struct {
	Result    Result
	Completed int
	Total     int
	Done      bool // true when all upgrades are finished (including go mod tidy)
	Err       error
}

// Updater handles upgrading selected Go module dependencies.
type Updater struct {
	runner  runner.CommandRunner
	workDir string
}

// NewUpdater creates an Updater that operates in the given directory.
func NewUpdater(runner runner.CommandRunner, workDir string) *Updater {
	return &Updater{
		runner:  runner,
		workDir: workDir,
	}
}

// Upgrade upgrades the selected dependencies and sends progress updates to the
// channel. It closes the channel when done.
//
// For each dependency it runs:
//
//	go get module@version
//
// After all upgrades it runs:
//
//	go mod tidy
//
// Context cancellation stops the process and leaves already-upgraded modules
// in their new state.
func (u *Updater) Upgrade(ctx context.Context, deps []module.Dependency, progress chan<- ProgressUpdate) {
	defer close(progress)

	total := len(deps)

	for i, dep := range deps {
		// Check for cancellation.
		if err := ctx.Err(); err != nil {
			progress <- ProgressUpdate{
				Result: Result{
					Path:    dep.Path,
					Success: false,
					Error:   "cancelled",
				},
				Completed: i,
				Total:     total,
				Done:      true,
				Err:       err,
			}
			return
		}

		result := u.upgradeOne(ctx, dep)
		progress <- ProgressUpdate{
			Result:    result,
			Completed: i + 1,
			Total:     total,
		}

		if !result.Success {
			// Report the failure and continue with remaining?
			// The spec says: do not hide failures. Continue so the user
			// sees all results.
			continue
		}
	}

	// Run go mod tidy after all upgrades.
	if err := u.runTidy(ctx); err != nil {
		progress <- ProgressUpdate{
			Completed: total,
			Total:     total,
			Done:      true,
			Err:       fmt.Errorf("go mod tidy failed: %w", err),
		}
		return
	}

	progress <- ProgressUpdate{
		Completed: total,
		Total:     total,
		Done:      true,
	}
}

func (u *Updater) upgradeOne(ctx context.Context, dep module.Dependency) Result {
	target := dep.Path + "@" + dep.LatestVersion
	_, err := u.runner.Run(ctx, "go", "-C", u.workDir, "get", target)
	if err != nil {
		return Result{
			Path:       dep.Path,
			OldVersion: dep.CurrentVersion,
			NewVersion: dep.LatestVersion,
			Success:    false,
			Error:      err.Error(),
		}
	}
	return Result{
		Path:       dep.Path,
		OldVersion: dep.CurrentVersion,
		NewVersion: dep.LatestVersion,
		Success:    true,
	}
}

func (u *Updater) runTidy(ctx context.Context) error {
	_, err := u.runner.Run(ctx, "go", "-C", u.workDir, "mod", "tidy")
	return err
}
