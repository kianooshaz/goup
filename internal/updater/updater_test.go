package updater

import (
	"context"
	"errors"
	"testing"

	"github.com/kianooshaz/goup/internal/module"
)

// fakeRunner implements runner.CommandRunner for testing.
type fakeRunner struct {
	stub  map[string]fakeResult
	calls []string
}

type fakeResult struct {
	output []byte
	err    error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.calls = append(f.calls, key)
	if f.stub == nil {
		return nil, nil
	}
	r, ok := f.stub[key]
	if !ok {
		return nil, errors.New("unexpected command: " + key)
	}
	return r.output, r.err
}

func TestUpgrade_Success(t *testing.T) {
	fake := &fakeRunner{
		stub: map[string]fakeResult{
			"go -C /test get github.com/foo/bar@v2.0.0": {output: []byte(""), err: nil},
			"go -C /test get github.com/foo/baz@v1.1.0": {output: []byte(""), err: nil},
			"go -C /test mod tidy":                       {output: []byte(""), err: nil},
		},
	}

	up := NewUpdater(fake, "/test")
	deps := []module.Dependency{
		{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/foo/baz", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}

	progress := make(chan ProgressUpdate, 10)
	go up.Upgrade(context.Background(), deps, progress)

	var results []Result
	var finalErr error
	for p := range progress {
		if p.Done {
			finalErr = p.Err
			break
		}
		results = append(results, p.Result)
	}

	if finalErr != nil {
		t.Errorf("unexpected error: %v", finalErr)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Success {
			t.Errorf("expected success for %s, got error: %s", r.Path, r.Error)
		}
	}

	// Verify the correct commands were called.
	expectedCalls := []string{
		"go -C /test get github.com/foo/bar@v2.0.0",
		"go -C /test get github.com/foo/baz@v1.1.0",
		"go -C /test mod tidy",
	}
	for i, call := range fake.calls {
		if i >= len(expectedCalls) {
			t.Errorf("unexpected call: %s", call)
			continue
		}
		if call != expectedCalls[i] {
			t.Errorf("call %d = %q, want %q", i, call, expectedCalls[i])
		}
	}
}

func TestUpgrade_PartialFailure(t *testing.T) {
	fake := &fakeRunner{
		stub: map[string]fakeResult{
			"go -C /test get github.com/foo/bar@v2.0.0": {output: []byte(""), err: nil},
			"go -C /test get github.com/foo/baz@v9.9.9": {output: nil, err: errors.New("not found")},
			"go -C /test mod tidy":                       {output: []byte(""), err: nil},
		},
	}

	up := NewUpdater(fake, "/test")
	deps := []module.Dependency{
		{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/foo/baz", CurrentVersion: "v1.0.0", LatestVersion: "v9.9.9"},
	}

	progress := make(chan ProgressUpdate, 10)
	go up.Upgrade(context.Background(), deps, progress)

	var results []Result
	for p := range progress {
		if !p.Done {
			results = append(results, p.Result)
		}
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	// First should succeed, second should fail.
	if !results[0].Success {
		t.Errorf("expected first to succeed, got error: %s", results[0].Error)
	}
	if results[1].Success {
		t.Errorf("expected second to fail, but it succeeded")
	}
}

func TestUpgrade_Cancellation(t *testing.T) {
	fake := &fakeRunner{
		stub: map[string]fakeResult{
			"go -C /test get github.com/foo/bar@v2.0.0": {output: []byte(""), err: nil},
		},
	}

	up := NewUpdater(fake, "/test")
	deps := []module.Dependency{
		{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "github.com/foo/baz", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	progress := make(chan ProgressUpdate, 10)

	go func() {
		// Cancel before the second upgrade starts.
		cancel()
	}()

	go up.Upgrade(ctx, deps, progress)

	var results []Result
	for p := range progress {
		if !p.Done {
			results = append(results, p.Result)
		}
	}
}

func TestUpgrade_NoDependencies(t *testing.T) {
	fake := &fakeRunner{
		stub: map[string]fakeResult{
			"go -C /test mod tidy": {output: []byte(""), err: nil},
		},
	}

	up := NewUpdater(fake, "/test")
	progress := make(chan ProgressUpdate, 10)
	go up.Upgrade(context.Background(), nil, progress)

	var results []Result
	for p := range progress {
		if !p.Done {
			results = append(results, p.Result)
		}
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for empty deps, got %d", len(results))
	}
}
