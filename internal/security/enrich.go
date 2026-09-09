package security

import (
	"context"
	"sort"

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

// Enrich checks every dependency and returns DependencyStatus values in
// the same order as the input slice.
func Enrich(ctx context.Context, checker *Checker, deps []module.Dependency) []DependencyStatus {
	requests := make([]Request, len(deps))
	for i, d := range deps {
		requests[i] = Request{Module: d.Path, Version: d.CurrentVersion}
	}

	statuses := checker.CheckAll(ctx, requests)

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

// FilterVulnerable keeps only dependencies with checked, confirmed
// vulnerabilities. Dependencies whose check failed are excluded from the
// security-only view (they cannot be honestly called "vulnerable" or
// "clean" — the failure is surfaced elsewhere).
func FilterVulnerable(items []DependencyStatus) []DependencyStatus {
	var out []DependencyStatus
	for _, it := range items {
		if it.Status.CheckedOK() && len(it.Status.Vulnerabilities) > 0 {
			out = append(out, it)
		}
	}
	return out
}

// SortBySecurity re-orders items in-place, most urgent first:
//  1. dependencies with known vulnerabilities (higher severity first)
//  2. dependencies whose check failed (so unavailability is visible)
//  3. everything else, preserving the input's direct/indirect ordering
func SortBySecurity(items []DependencyStatus) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]

		ai := urgency(a)
		bi := urgency(b)
		if ai != bi {
			return ai > bi // higher urgency first
		}
		// Within a group keep the caller's deterministic order (direct
		// first, then by path, as produced by module.SortDependencies).
		return false
	})
}

// urgency ranks an item: vulnerable deps by severity, failed checks above
// clean deps, clean deps last.
func urgency(item DependencyStatus) int {
	switch {
	case item.Status.CheckedOK() && len(item.Status.Vulnerabilities) > 0:
		// Severity ranks Low(2) .. Critical(5); Unknown(0) still counts as
		// an issue so it sorts above clean deps but below known severity.
		return 10 + item.Status.Severity.Rank()
	case !item.Status.CheckedOK():
		return 5
	default:
		return 0
	}
}
