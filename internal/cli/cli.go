package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/runner"
	"github.com/kianooshaz/goup/internal/tui"
	"github.com/kianooshaz/goup/internal/updater"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Config holds the parsed CLI configuration.
type Config struct {
	Indirect bool
	Dir      string
	ShowVer  bool
	ShowHelp bool
}

// Run parses CLI flags and runs the goup workflow.
func Run(args []string) int {
	cfg, err := parseFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		return 1
	}

	if cfg.ShowVer {
		fmt.Printf("goup %s\n", Version)
		return 0
	}

	workDir := cfg.Dir
	if workDir == "" {
		workDir, _ = os.Getwd()
	}

	// Check that go.mod exists.
	if _, err := os.Stat(workDir + "/go.mod"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ No go.mod found in the current directory.\n\n")
		fmt.Fprintf(os.Stderr, "  goup must be run inside a Go module.\n")
		return 1
	}

	// Create runner and discoverer.
	cmdRunner := runner.NewOSCommandRunner()
	disc := module.NewDiscoverer(cmdRunner, workDir)

	// Discover outdated dependencies.
	ctx := context.Background()
	deps, err := disc.Discover(ctx, cfg.Indirect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to discover Go dependencies.\n\n")
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		fmt.Fprintf(os.Stderr, "\n  Check your Go installation and module configuration.\n")
		return 1
	}

	// No updates available.
	if len(deps) == 0 {
		if cfg.Indirect {
			fmt.Println("✓ All dependencies (direct + indirect) are up to date.")
		} else {
			fmt.Println("✓ All direct dependencies are up to date.")
		}
		return 0
	}

	// Check if stdin is a terminal.
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		fmt.Fprintf(os.Stderr, "✗ Interactive mode requires a terminal.\n\n")
		fmt.Fprintf(os.Stderr, "  Run goup in an interactive terminal session.\n")
		return 1
	}

	// Create updater and TUI model.
	up := updater.NewUpdater(cmdRunner, workDir)
	model := tui.NewModel(deps, up)

	// Run the TUI program.
	p := tea.NewProgram(model, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ TUI error: %v\n", err)
		return 1
	}

	final, ok := finalModel.(*tui.Model)
	if !ok {
		return 0
	}

	// Determine exit code based on upgrade results.
	if final.HasSelection() {
		// If we went through the upgrade flow and had failures, return non-zero.
		// We don't track final success/failure state yet; that's OK for now.
	}

	return 0
}

// parseFlags parses CLI arguments.
func parseFlags(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("goup", flag.ContinueOnError)
	fs.BoolVar(&c.Indirect, "indirect", false, "Include indirect dependencies")
	fs.StringVar(&c.Dir, "dir", "", "Go module directory (default: current directory)")
	fs.BoolVar(&c.ShowVer, "version", false, "Show version")
	fs.BoolVar(&c.ShowHelp, "help", false, "Show help")
	fs.BoolVar(&c.ShowHelp, "h", false, "Show help")

	// Custom usage.
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `goup — interactive Go dependency updater

Usage:
  goup [flags]

Flags:
  --indirect    Include indirect dependencies
  --dir string  Go module directory (default: current directory)
  --version     Show version
  -h, --help    Show help
`)
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if c.ShowHelp {
		fs.Usage()
		return nil, flag.ErrHelp
	}

	return c, nil
}
