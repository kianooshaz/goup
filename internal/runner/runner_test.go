package runner

import (
	"context"
	"errors"
	"testing"
)

// FakeCommandRunner implements CommandRunner for testing.
type FakeCommandRunner struct {
	// Stub defines per-command behavior.
	// Key is command name + args joined.
	Stub  map[string]FakeResult
	Calls []string
}

type FakeResult struct {
	Output []byte
	Err    error
}

func (f *FakeCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	f.Calls = append(f.Calls, key)
	if f.Stub == nil {
		return nil, nil
	}
	r, ok := f.Stub[key]
	if !ok {
		return nil, errors.New("unexpected command: " + key)
	}
	return r.Output, r.Err
}

func TestFakeCommandRunner(t *testing.T) {
	f := &FakeCommandRunner{
		Stub: map[string]FakeResult{
			"go version": {Output: []byte("go version go1.21.0"), Err: nil},
		},
	}

	out, err := f.Run(context.Background(), "go", "version")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if string(out) != "go version go1.21.0" {
		t.Errorf("got %q, want %q", string(out), "go version go1.21.0")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "go version" {
		t.Errorf("calls = %v, want [go version]", f.Calls)
	}
}

func TestOSCommandRunnerInterface(t *testing.T) {
	// Verify OSCommandRunner satisfies the interface at compile time.
	var _ CommandRunner = (*OSCommandRunner)(nil)
}
