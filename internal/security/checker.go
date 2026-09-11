package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrUnavailable is returned by a check that could not reach the
// vulnerability database. Callers must distinguish it from "no known
// vulnerabilities": an unreachable database must never be rendered as a
// clean bill of health.
var ErrUnavailable = errors.New("security information unavailable")

// ErrPrivateModule is recorded on statuses for modules skipped by the
// privacy heuristic. Such modules are never queried against the database.
var ErrPrivateModule = errors.New("private module: not queried")

// Default per-module lookup bound: one slow/unreachable lookup must not
// stall the interactive check.
const perModuleTimeout = 5 * time.Second

// Checker enriches a dependency list with security statuses, aligned
// by index with the input slice.
type Checker struct {
	provider Provider
	cache    *DiskCache
	// PerModuleTimeout bounds a single module's vulnerability lookup.
	// Zero uses the default (5s); a negative value disables the bound.
	PerModuleTimeout time.Duration
}

// NewChecker creates a Checker. cache may be nil (no caching).
func NewChecker(provider Provider, cache *DiskCache) *Checker {
	return &Checker{provider: provider, cache: cache}
}

// ProgressFunc is called as each module's check completes (or fails).
// done counts completed lookups (including cached/skipped ones when
// convenient for the caller); total is the number of requests. It must
// be safe to call concurrently.
type ProgressFunc func(done, total int, module string)

// CheckAll resolves a status for every module@version. It never fails
// wholesale: per-dependency failures (network errors, timeouts) are
// recorded on that dependency's status so the UI can show "check failed"
// for the affected rows while still presenting fresh results for the
// rest. ctx cancellation stops outstanding work.
func (c *Checker) CheckAll(ctx context.Context, requests []Request) []Status {
	return c.CheckAllWithProgress(ctx, requests, nil)
}

// CheckAllWithProgress is CheckAll with a progress callback invoked after
// each module lookup completes.
func (c *Checker) CheckAllWithProgress(ctx context.Context, requests []Request, progress ProgressFunc) []Status {
	statuses := make([]Status, len(requests))

	type job struct {
		index   int
		module  string
		version string
	}

	var (
		jobs    []job
		wg      sync.WaitGroup
		mu      sync.Mutex
		cacheMu sync.Mutex
	)

	for i, r := range requests {
		if IsPrivateModule(r.Module) {
			statuses[i] = Status{Checked: false, Err: ErrPrivateModule}
			continue
		}
		if vulns, ok := c.cache.Get(r.Module, r.Version); ok {
			statuses[i] = newCheckedStatus(vulns)
			continue
		}
		jobs = append(jobs, job{i, r.Module, r.Version})
	}

	completed := 0
	total := len(requests)

	// Bounded concurrency: the OSV API is a shared public service.
	sem := make(chan struct{}, 8)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			checkCtx := ctx
			var cancel context.CancelFunc
			if timeout := c.timeout(); timeout > 0 {
				checkCtx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

			vulns, err := c.provider.Check(checkCtx, j.module, j.version)
			if err != nil {
				mu.Lock()
				statuses[j.index] = Status{Checked: false, Err: fmt.Errorf("%w: %v", ErrUnavailable, err)}
				mu.Unlock()
			} else {
				mu.Lock()
				statuses[j.index] = newCheckedStatus(vulns)
				mu.Unlock()
				cacheMu.Lock()
				c.cache.Put(j.module, j.version, vulns)
				cacheMu.Unlock()
			}
			if progress != nil {
				// Count under the lock, then report outside it: the callback
				// can block (the pipeline forwards it to a bounded channel),
				// and holding mu across that would stall every other worker.
				mu.Lock()
				completed++
				done := completed
				mu.Unlock()
				progress(done, total, j.module)
			}
		}(j)
	}
	wg.Wait()

	return statuses
}

// timeout resolves the effective per-module timeout: explicit value,
// default, or disabled for negative values.
func (c *Checker) timeout() time.Duration {
	switch {
	case c.PerModuleTimeout > 0:
		return c.PerModuleTimeout
	case c.PerModuleTimeout < 0:
		return 0
	default:
		return perModuleTimeout
	}
}

// Request is one module@version to check.
type Request struct {
	Module  string
	Version string
}

// newCheckedStatus builds a fully-checked status from vulnerabilities,
// computing the worst severity.
func newCheckedStatus(vulns []Vulnerability) Status {
	return Status{
		Vulnerabilities: vulns,
		Severity:        worstSeverity(vulns),
		Checked:         true,
	}
}

// IsPrivateModule applies a conservative heuristic: module paths whose
// first element has no dot (e.g. "corp/internal-lib") cannot be hosted on
// a public module proxy and are almost certainly private or workspace-local.
// They are skipped rather than sent to an external service. Well-known
// public hosts are always treated as public.
func IsPrivateModule(modulePath string) bool {
	first := modulePath
	if i := strings.IndexByte(modulePath, '/'); i >= 0 {
		first = modulePath[:i]
	}
	if first == "" {
		return true
	}
	if strings.Contains(first, ".") {
		return false
	}
	// gopkg.in and similar vanity-less hosts still carry a dot; a dotless
	// first element is private by Go's own module path rules.
	return true
}
