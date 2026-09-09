package runner

import (
	"context"
	"os/exec"
)

// CommandRunner abstracts command execution so it can be replaced in tests.
type CommandRunner interface {
	// Run executes a command and returns its stdout. It returns an error if
	// the command fails (stderr is included in the error message when possible).
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OSCommandRunner runs commands using the real OS.
type OSCommandRunner struct{}

func NewOSCommandRunner() *OSCommandRunner {
	return &OSCommandRunner{}
}

func (r *OSCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, &RunError{
				ExitCode: exitErr.ExitCode(),
				Stderr:   string(exitErr.Stderr),
				Cause:    err,
			}
		}
		return out, err
	}
	return out, nil
}

// RunError wraps command execution failures with exit code and stderr.
type RunError struct {
	ExitCode int
	Stderr   string
	Cause    error
}

func (e *RunError) Error() string {
	if e.Stderr != "" {
		return e.Stderr
	}
	return e.Cause.Error()
}

func (e *RunError) Unwrap() error {
	return e.Cause
}

// Ensure OSCommandRunner implements CommandRunner.
var _ CommandRunner = (*OSCommandRunner)(nil)
