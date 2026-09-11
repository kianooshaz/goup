package security

import (
	"context"

	"github.com/kianooshaz/goup/internal/module"
)

// DependencyStatus is the security view of one dependency: the dependency,
// its vulnerability status, and the remediation assessment for the
// currently available upgrade.
type DependencyStatus struct {
	Dependency module.Dependency
	Status     Status
	Fix        FixAssessment
}

// EnrichWithStatuses combines dependencies with already-computed statuses
// (aligned by index) and computes fix assessments. It is the single entry
// point for turning statuses into the UI's view model, used both by the
// background pipeline (which runs the check itself, with progress
// reporting) and by callers that only need the check.
func EnrichWithStatuses(deps []module.Dependency, statuses []Status) []DependencyStatus {
	result := make([]DependencyStatus, len(deps))
	for i, d := range deps {
		s := statuses[i]
		fix := FixUnknown
		if s.CheckedOK() {
			fix = AssessFix(d.CurrentVersion, d.LatestVersion, s.Vulnerabilities)
		}
		result[i] = DependencyStatus{
			Dependency: d,
			Status:     s,
			Fix:        fix,
		}
	}
	return result
}

// Enrich checks every dependency and returns DependencyStatus values in
// the same order as the input slice.
func Enrich(ctx context.Context, checker *Checker, deps []module.Dependency) []DependencyStatus {
	requests := make([]Request, len(deps))
	for i, d := range deps {
		requests[i] = Request{Module: d.Path, Version: d.CurrentVersion}
	}

	return EnrichWithStatuses(deps, checker.CheckAll(ctx, requests))
}
