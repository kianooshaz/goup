package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/runner"
	"github.com/kianooshaz/goup/internal/security"
	"github.com/kianooshaz/goup/internal/tui"
	"github.com/kianooshaz/goup/internal/updater"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Config holds the parsed CLI configuration.
type Config struct {
	Indirect   bool
	Dir        string
	ShowVer    bool
	ShowHelp   bool
	Security   bool // --security: prioritize/filter by security issues
	NoSecurity bool // --no-security: skip the vulnerability check
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

	// Security check: enrich the dependency list before opening the TUI.
	var secStatuses []security.DependencyStatus
	secMode := tui.SecurityOn
	if cfg.NoSecurity {
		secMode = tui.SecurityOff
	} else {
		fmt.Printf("Checking vulnerabilities for %d dependencies...\n", len(deps))
		secStatuses = checkSecurity(ctx, deps)
		if cfg.Security {
			secMode = tui.SecurityOnly
		}
	}

	// Security-only mode with nothing to show: say so and exit cleanly.
	if secMode == tui.SecurityOnly {
		vulnerable := 0
		for _, s := range secStatuses {
			if s.Status.CheckedOK() && len(s.Status.Vulnerabilities) > 0 {
				vulnerable++
			}
		}
		if vulnerable == 0 {
			fmt.Println("✓ No vulnerable dependencies among the available updates.")
			printSecurityCaveat(secStatuses)
			return 0
		}
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
	model := tui.NewModel(deps, secStatuses, secMode, up)

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

// checkSecurity runs the vulnerability check for all dependencies with a
// disk cache. Failures are recorded per dependency, never fatal: the UI
// shows an explicit "unavailable" state rather than a false "✓ secure".
func checkSecurity(ctx context.Context, deps []module.Dependency) []security.DependencyStatus {
	provider := security.NewOSVProvider()
	cache := security.NewDiskCache(security.DefaultCachePath())
	checker := security.NewChecker(provider, cache)

	start := time.Now()
	items := security.Enrich(ctx, checker, deps)

	// Warn once when the whole check failed so the user understands the
	// badges they are (not) seeing.
	failed := 0
	for _, it := range items {
		if !it.Status.CheckedOK() {
			failed++
		}
	}
	if failed == len(deps) && len(deps) > 0 {
		fmt.Fprintf(os.Stderr, "⚠ Security check failed: %v\n", items[0].Status.Err)
	} else {
		fmt.Printf("Security check done in %s.\n", time.Since(start).Round(100*time.Millisecond))
	}
	return items
}

// printSecurityCaveat explains why a clean result is not a guarantee when
// some checks could not run (offline, private modules).
func printSecurityCaveat(items []security.DependencyStatus) {
	var reasons []string
	for _, it := range items {
		if it.Status.CheckedOK() || it.Status.Err == nil {
			continue
		}
		reasons = append(reasons, "  - "+it.Dependency.Path+": "+it.Status.Err.Error())
	}
	if len(reasons) > 0 {
		fmt.Fprintf(os.Stderr, "⚠ Some dependencies could not be checked:\n%s\n",
			strings.Join(reasons, "\n"))
	}
}

// parseFlags parses CLI arguments.
func parseFlags(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("goup", flag.ContinueOnError)
	fs.BoolVar(&c.Indirect, "indirect", false, "Include indirect dependencies")
	fs.StringVar(&c.Dir, "dir", "", "Go module directory (default: current directory)")
	fs.BoolVar(&c.Security, "security", false, "Show only dependencies with security issues")
	fs.BoolVar(&c.NoSecurity, "no-security", false, "Skip the vulnerability check")
	fs.BoolVar(&c.ShowVer, "version", false, "Show version")
	fs.BoolVar(&c.ShowHelp, "help", false, "Show help")
	fs.BoolVar(&c.ShowHelp, "h", false, "Show help")

	// Custom usage.
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `goup — interactive Go dependency updater

Usage:
  goup [flags]

Flags:
  --indirect      Include indirect dependencies
  --security      Show only dependencies with security issues
  --no-security   Skip the vulnerability check
  --dir string    Go module directory (default: current directory)
  --version       Show version
  -h, --help      Show help
`)
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if c.Security && c.NoSecurity {
		return nil, fmt.Errorf("--security and --no-security cannot be combined")
	}

	if c.ShowHelp {
		fs.Usage()
		return nil, flag.ErrHelp
	}

	return c, nil
}
