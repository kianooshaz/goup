// Package pipeline orchestrates dependency discovery and the security
// check as a background phase, emitting progress events and a final
// structured result. The Bubble Tea UI drives it through commands and
// messages and never blocks on discovery itself.
package pipeline

import (
	"context"
	"time"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/security"
)

// Stage identifies what the pipeline is currently doing.
type Stage int

const (
	StageReading  Stage = iota // reading go.mod / running go list
	StageSecurity              // checking vulnerabilities
	StageDone
)

// String renders the stage for the loading view.
func (s Stage) String() string {
	switch s {
	case StageReading:
		return "Discovering dependencies..."
	case StageSecurity:
		return "Checking for known vulnerabilities..."
	default:
		return "Done"
	}
}

// Progress is a snapshot of what the pipeline is doing right now, sent
// to the UI as a message. Operations are cheap to render.
type Progress struct {
	Stage  Stage
	Module string // module currently being processed, if any
	Done   int    // completed items in the current stage
	Total  int    // total items in the current stage (0 = unknown)
}

// Result is the structured outcome of the whole pipeline.
type Result struct {
	// Dependencies with available updates.
	Dependencies []module.Dependency
	// Modules that could not be processed, isolated per module.
	Skipped []module.SkippedDependency
	// Security statuses aligned by index with Dependencies; nil when the
	// security check is disabled.
	Security []security.DependencyStatus
	// SecurityFailed reports whether the security check could not run at
	// all (e.g. disabled by flag).
	SecurityDisabled bool
}

// Pipeline ties discovery and the security check together.
type Pipeline struct {
	discoverer *module.Discoverer
	checker    *security.Checker
}

// New creates a Pipeline. checker may be nil to skip the security phase.
func New(discoverer *module.Discoverer, checker *security.Checker) *Pipeline {
	return &Pipeline{discoverer: discoverer, checker: checker}
}

// Run executes the pipeline synchronously, sending Progress snapshots on
// progress as work advances, and the final Result on results. Exactly one
// Result is sent; progress is closed when Run returns. Failures are
// isolated per module: a module that cannot be discovered or checked is
// skipped while everything else continues. Only a fatal failure (go
// itself unusable, context cancelled) produces an error. securityOn=false
// skips the security phase entirely.
func (p *Pipeline) Run(ctx context.Context, includeIndirect bool, securityOn bool, progress chan<- Progress, results chan<- Result, errs chan<- error) {
	defer close(progress)

	// send emits a progress snapshot, abandoning it if the context ends.
	send := func(pr Progress) {
		select {
		case progress <- pr:
		case <-ctx.Done():
		}
	}

	// deliver puts exactly one outcome on results or errs. The channels
	// are buffered by the contract; if the consumer vanished the context
	// decides — the outcome is dropped rather than blocking forever.
	deliver := func(res Result, err error) {
		if err != nil {
			select {
			case errs <- err:
				return
			default:
			}
			<-ctx.Done()
			return
		}
		select {
		case results <- res:
			return
		default:
		}
		<-ctx.Done()
	}

	send(Progress{Stage: StageReading})

	disc, err := p.discoverer.Discover(ctx, includeIndirect)
	if err != nil {
		deliver(Result{}, err)
		return
	}
	skipped := disc.Skipped
	send(Progress{Stage: StageReading, Done: 1, Total: 1})

	if p.checker == nil || !securityOn {
		deliver(Result{
			Dependencies:     disc.Dependencies,
			Skipped:          skipped,
			SecurityDisabled: true,
		}, nil)
		return
	}

	send(Progress{Stage: StageSecurity, Total: len(disc.Dependencies)})

	requests := make([]security.Request, len(disc.Dependencies))
	for i, d := range disc.Dependencies {
		requests[i] = security.Request{Module: d.Path, Version: d.CurrentVersion}
	}

	statuses := p.checker.CheckAllWithProgress(ctx, requests, func(done, total int, mod string) {
		send(Progress{Stage: StageSecurity, Module: mod, Done: done, Total: total})
	})

	items := security.EnrichWithStatuses(disc.Dependencies, statuses)

	send(Progress{Stage: StageDone})
	deliver(Result{
		Dependencies: disc.Dependencies,
		Skipped:      skipped,
		Security:     items,
	}, nil)
}

// Deadline is the overall discovery bound. Individual dependency checks
// have their own shorter timeouts; this guards the whole phase so the UI
// is never stuck in loading forever.
const Deadline = 2 * time.Minute
