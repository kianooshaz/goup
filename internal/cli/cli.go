package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/pipeline"
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
	Security   bool // --security: show only dependencies with known vulnerabilities
	NoSecurity bool // --no-security: skip the vulnerability check
}

// Run parses CLI flags and runs the goup workflow. The TUI starts
// immediately in a loading state while discovery and the security check
// run in the background; a failure to check one dependency never stops
// the rest.
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
	if _, err := os.Stat(filepath.Join(workDir, "go.mod")); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ No go.mod found in the current directory.\n\n")
		fmt.Fprintf(os.Stderr, "  goup must be run inside a Go module.\n")
		return 1
	}

	// Check if stdin is a terminal before starting the TUI. A failed Stat
	// means we cannot prove it is one, so treat it as non-interactive
	// rather than dereferencing a nil FileInfo.
	stat, err := os.Stdin.Stat()
	if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
		fmt.Fprintf(os.Stderr, "✗ Interactive mode requires a terminal.\n\n")
		fmt.Fprintf(os.Stderr, "  Run goup in an interactive terminal session.\n")
		return 1
	}

	// Build the pipeline: discovery + optional security check. The mode
	// decides both whether the check runs and how the list is presented.
	cmdRunner := runner.NewOSCommandRunner()
	disc := module.NewDiscoverer(cmdRunner, workDir)

	mode := securityMode(cfg)
	var checker *security.Checker
	if mode != tui.SecurityOff {
		checker = security.NewChecker(
			security.NewOSVProvider(),
			security.NewDiskCache(security.DefaultCachePath()),
		)
	}
	pipe := pipeline.New(disc, checker)

	up := updater.NewUpdater(cmdRunner, workDir)
	model := tui.NewModel(up, mode)
	// The pipeline launches as the program's initial command; the loading
	// screen renders immediately and stays responsive.
	model.SetInitCmd(model.StartPipeline(pipe, cfg.Indirect))

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ TUI error: %v\n", err)
		return 1
	}

	return 0
}

// securityMode maps the parsed flags to the TUI's security presentation
// mode. --security narrows the list to vulnerable dependencies and still
// runs the check; --no-security skips it entirely. Combining the two is
// rejected during parsing, so no precedence rule is needed here.
func securityMode(c *Config) tui.SecurityMode {
	switch {
	case c.NoSecurity:
		return tui.SecurityOff
	case c.Security:
		return tui.SecurityOnly
	default:
		return tui.SecurityOn
	}
}

// parseFlags parses CLI arguments.
func parseFlags(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("goup", flag.ContinueOnError)
	fs.BoolVar(&c.Indirect, "indirect", false, "Include indirect dependencies")
	fs.StringVar(&c.Dir, "dir", "", "Go module directory (default: current directory)")
	fs.BoolVar(&c.Security, "security", false, "Show only dependencies with known vulnerabilities")
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
  --security      Show only dependencies with known vulnerabilities
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
