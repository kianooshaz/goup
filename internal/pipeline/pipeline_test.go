package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/security"
)

// fakeRunner executes canned output for "go" commands, with optional
// failure or delay, so discovery is tested without a real toolchain.
type fakeRunner struct {
	output string
	err    error
	delay  time.Duration
	calls  int
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return []byte(f.output), f.err
	}
	return []byte(f.output), nil
}

// newDiscoverer builds a Discoverer backed by the fake runner.
func newDiscoverer(f *fakeRunner) *module.Discoverer {
	return module.NewDiscoverer(f, "/tmp/does-not-matter")
}

// moduleJSON builds one go list record with an update.
func moduleJSON(path, version, latest string) string {
	return fmt.Sprintf(`{"path":%q,"version":%q,"update":{"path":%q,"version":%q}}`,
		path, version, path, latest)
}

// failedModuleJSON builds a record with a load error (the -e case).
func failedModuleJSON(path, errMsg string) string {
	return fmt.Sprintf(`{"path":%q,"error":{"Err":%q}}`, path, errMsg)
}

// collect runs the pipeline synchronously and returns everything sent.
func collect(ctx context.Context, p *Pipeline, includeIndirect, securityOn bool) (Result, []Progress, error) {
	progress := make(chan Progress, 64)
	results := make(chan Result, 1)
	errs := make(chan error, 1)

	var allProgress []Progress
	done := make(chan struct{})
	go func() {
		for pr := range progress {
			allProgress = append(allProgress, pr)
		}
		close(done)
	}()

	go p.Run(ctx, includeIndirect, securityOn, progress, results, errs)

	var res Result
	var runErr error
	select {
	case res = <-results:
	case err := <-errs:
		runErr = err
	}
	<-done
	return res, allProgress, runErr
}

// --- Successful discovery ---

func TestRunSuccessfulDiscovery(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/a", "v1.0.0", "v1.1.0") +
		"\n" + moduleJSON("github.com/b", "v2.0.0", "v2.1.0")}
	p := New(newDiscoverer(f), nil) // security disabled

	res, progress, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(res.Dependencies))
	}
	if len(res.Skipped) != 0 {
		t.Errorf("expected no skips, got %+v", res.Skipped)
	}
	// Progress must include a reading stage event.
	sawReading := false
	for _, pr := range progress {
		if pr.Stage == StageReading {
			sawReading = true
		}
	}
	if !sawReading {
		t.Error("progress should include the reading stage")
	}
}

// --- Partial failures are isolated ---

func TestRunPartialFailureSkipsBadModules(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/good", "v1.0.0", "v1.1.0") +
		"\n" + failedModuleJSON("github.com/broken", "cannot find module") +
		"\n" + moduleJSON("github.com/also-good", "v1.0.0", "v1.2.0")}
	p := New(newDiscoverer(f), nil)

	res, _, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("partial failure must not be a fatal error: %v", err)
	}
	if len(res.Dependencies) != 2 {
		t.Errorf("healthy dependencies must survive: got %d, want 2", len(res.Dependencies))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("expected 1 skipped, got %+v", res.Skipped)
	}
	if res.Skipped[0].Path != "github.com/broken" {
		t.Errorf("skipped path = %q, want github.com/broken", res.Skipped[0].Path)
	}
	if res.Skipped[0].Reason == nil || !strings.Contains(res.Skipped[0].Reason.Error(), "cannot find module") {
		t.Errorf("skip reason should carry the go error: %v", res.Skipped[0].Reason)
	}
}

// --- Fatal runner failure (go itself unusable) ---

func TestRunFatalDiscoveryError(t *testing.T) {
	f := &fakeRunner{err: errors.New("go: command not usable")}
	p := New(newDiscoverer(f), nil)

	_, _, err := collect(context.Background(), p, false, true)
	if err == nil {
		t.Fatal("expected a fatal error when go list fails entirely")
	}
}

// --- Malformed JSON record: keep earlier modules, record a skip ---

func TestRunMalformedRecord(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/ok", "v1.0.0", "v1.1.0") +
		"\n{not json"}
	p := New(newDiscoverer(f), nil)

	res, _, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("malformed tail must not be fatal: %v", err)
	}
	if len(res.Dependencies) != 1 {
		t.Errorf("earlier dependency should survive: got %d", len(res.Dependencies))
	}
	if len(res.Skipped) != 1 {
		t.Errorf("malformed record should be skipped, got %+v", res.Skipped)
	}
}

// --- Indirect filter still applies through the pipeline ---

func TestRunIndirectFilter(t *testing.T) {
	f := &fakeRunner{output: `{"path":"github.com/direct","version":"v1.0.0","indirect":false,"update":{"version":"v1.1.0"}}` + "\n" +
		`{"path":"github.com/ind","version":"v1.0.0","indirect":true,"update":{"version":"v1.1.0"}}`}
	p := New(newDiscoverer(f), nil)

	res, _, _ := collect(context.Background(), p, false, true)
	if len(res.Dependencies) != 1 {
		t.Fatalf("indirect should be excluded: %+v", res.Dependencies)
	}

	res, _, _ = collect(context.Background(), p, true, true)
	if len(res.Dependencies) != 2 {
		t.Fatalf("indirect should be included with flag: got %d", len(res.Dependencies))
	}
}

// --- Security phase runs and reports progress ---

type fakeProvider struct {
	vulns map[string][]security.Vulnerability
	err   error
	delay time.Duration
}

func (f *fakeProvider) Check(ctx context.Context, mod, ver string) ([]security.Vulnerability, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.vulns[mod], nil
}

func TestRunWithSecurityProgress(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/a", "v1.0.0", "v1.1.0") +
		"\n" + moduleJSON("github.com/b", "v1.0.0", "v1.1.0")}
	provider := &fakeProvider{vulns: map[string][]security.Vulnerability{
		"github.com/a": {{ID: "GO-2026-1", Severity: security.SeverityHigh}},
	}}
	checker := security.NewChecker(provider, nil)
	p := New(newDiscoverer(f), checker)

	res, progress, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Security) != 2 {
		t.Fatalf("security statuses should align with deps, got %d", len(res.Security))
	}
	if res.Security[0].Status.Severity != security.SeverityHigh {
		t.Errorf("vulnerability should be attached, got %+v", res.Security[0])
	}

	// Security progress events must name modules and advance.
	securityEvents := 0
	for _, pr := range progress {
		if pr.Stage == StageSecurity {
			securityEvents++
			if pr.Total != 2 {
				t.Errorf("security progress total = %d, want 2", pr.Total)
			}
		}
	}
	if securityEvents == 0 {
		t.Error("expected security progress events")
	}
}

// --- Security failure isolated per module ---

func TestRunSecurityFailureIsolated(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/a", "v1.0.0", "v1.1.0") +
		"\n" + moduleJSON("github.com/b", "v1.0.0", "v1.1.0")}
	provider := &fakeProvider{err: errors.New("network unreachable")}
	checker := security.NewChecker(provider, nil)
	p := New(newDiscoverer(f), checker)

	res, _, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("provider failure must not fail the pipeline: %v", err)
	}
	for i, item := range res.Security {
		if item.Status.CheckedOK() {
			t.Errorf("statuses[%d] should record the failure, not look clean", i)
		}
	}
}

// --- Security disabled by flag: no provider calls at all ---

func TestRunSecurityOff(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/a", "v1.0.0", "v1.1.0")}
	provider := &fakeProvider{}
	checker := security.NewChecker(provider, nil)
	p := New(newDiscoverer(f), checker)

	res, _, _ := collect(context.Background(), p, false, false)
	if !res.SecurityDisabled {
		t.Error("result should mark security as disabled")
	}
	if len(res.Security) != 0 {
		t.Errorf("no security data should be attached, got %d", len(res.Security))
	}
}

// --- Timeout: slow provider results in unchecked statuses, not hang ---

func TestRunProviderTimeout(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/slow", "v1.0.0", "v1.1.0")}
	provider := &fakeProvider{delay: 5 * time.Second}
	checker := security.NewChecker(provider, nil)
	checker.PerModuleTimeout = 50 * time.Millisecond
	p := New(newDiscoverer(f), checker)

	start := time.Now()
	res, _, err := collect(context.Background(), p, false, true)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("per-module timeout must not fail the pipeline: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout should bound the wait, took %s", elapsed)
	}
	if len(res.Security) != 1 {
		t.Fatalf("expected a status for the slow module, got %d", len(res.Security))
	}
	if res.Security[0].Status.CheckedOK() {
		t.Error("timed-out module must not look checked/clean")
	}
}

// --- Cancellation: pipeline stops promptly ---

func TestRunCancellation(t *testing.T) {
	f := &fakeRunner{delay: 10 * time.Second}
	p := New(newDiscoverer(f), nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := collect(ctx, p, false, true)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error after cancellation")
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation should be prompt, took %s", elapsed)
	}
}

// --- All dependencies failed at the security layer: still a valid result ---

func TestRunAllSecurityChecksFailed(t *testing.T) {
	f := &fakeRunner{output: moduleJSON("github.com/a", "v1.0.0", "v1.1.0") +
		"\n" + moduleJSON("github.com/b", "v1.0.0", "v1.1.0")}
	provider := &fakeProvider{err: errors.New("offline")}
	checker := security.NewChecker(provider, nil)
	p := New(newDiscoverer(f), checker)

	res, _, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("all-failed security must still produce results: %v", err)
	}
	if len(res.Dependencies) != 2 {
		t.Errorf("dependencies must still be delivered, got %d", len(res.Dependencies))
	}
	for i, item := range res.Security {
		if item.Status.Checked || item.Status.Severity == security.SeverityNone {
			t.Errorf("statuses[%d] must not present as clean", i)
		}
	}
}

// --- Discovery skips all modules: empty but valid result ---

func TestRunAllModulesFailed(t *testing.T) {
	f := &fakeRunner{output: failedModuleJSON("github.com/x", "boom") +
		"\n" + failedModuleJSON("github.com/y", "also boom")}
	p := New(newDiscoverer(f), nil)

	res, _, err := collect(context.Background(), p, false, true)
	if err != nil {
		t.Fatalf("all-skipped discovery must not be fatal: %v", err)
	}
	if len(res.Dependencies) != 0 {
		t.Errorf("expected no dependencies, got %d", len(res.Dependencies))
	}
	if len(res.Skipped) != 2 {
		t.Errorf("expected 2 skips, got %+v", res.Skipped)
	}
}
