package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/pipeline"
	"github.com/kianooshaz/goup/internal/runner"
	"github.com/kianooshaz/goup/internal/security"
)

// These tests drive the model the way Bubble Tea actually does — executing
// the commands Update returns, feeding their messages back in, and
// re-executing whatever comes out — instead of poking model fields
// directly. That is the only way to catch a command chain that stops
// delivering events, which is exactly how the loading screen used to strand
// the UI.

// listRunner is a fake CommandRunner returning canned `go list` output.
type listRunner struct {
	output string
	err    error
}

func (r *listRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return []byte(r.output), r.err
}

// stubProvider is a fake security.Provider keyed by module path.
type stubProvider struct {
	vulns map[string][]security.Vulnerability
	err   error
}

func (p *stubProvider) Check(_ context.Context, mod, _ string) ([]security.Vulnerability, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.vulns[mod], nil
}

// goListJSON builds one `go list -m -u -e -json` record.
func goListJSON(path, current, latest string) string {
	return fmt.Sprintf(`{"path":%q,"version":%q,"update":{"path":%q,"version":%q}}`,
		path, current, path, latest)
}

// runProgram drives m to quiescence: every command runs in its own
// goroutine (as Bubble Tea does), its message is fed back to Update, and the
// commands Update returns are executed in turn. It stops when no command is
// in flight and no message is pending, and fails the test if that never
// happens within the budget.
func runProgram(t *testing.T, m *Model, first tea.Cmd, budget time.Duration) {
	t.Helper()

	msgs := make(chan tea.Msg, 128)
	var inflight atomic.Int64

	dispatch := func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		inflight.Add(1)
		go func() {
			defer inflight.Add(-1)
			msgs <- cmd()
		}()
	}

	dispatch(first)

	start := time.Now()
	for {
		drained := false
		for {
			var msg tea.Msg
			select {
			case msg = <-msgs:
			default:
				msg = nil
			}
			// A nil message means the command returned nothing (the
			// pipeline stream ended), so there is nothing left to feed in.
			if msg == nil {
				break
			}
			// Bubble Tea's runtime expands a batch into its member
			// commands; the harness has to do the same, otherwise a
			// batched Init would look like a no-op.
			if batch, ok := msg.(tea.BatchMsg); ok {
				for _, c := range batch {
					dispatch(c)
				}
				drained = true
				continue
			}
			_, next := m.Update(msg)
			dispatch(next)
			drained = true
		}
		if !drained && inflight.Load() == 0 {
			return
		}
		if time.Since(start) > budget {
			t.Fatalf("program did not settle within %s (screen=%v, stage=%v)",
				budget, m.screen, m.loadingStage)
		}
		time.Sleep(time.Millisecond)
	}
}

// startModel wires a real pipeline over the fakes and returns the model
// plus the command Bubble Tea would run first, mirroring the CLI's
// SetInitCmd(model.StartPipeline(...)) sequence.
func startModel(t *testing.T, r runner.CommandRunner, provider security.Provider, mode SecurityMode) (*Model, tea.Cmd) {
	t.Helper()
	disc := module.NewDiscoverer(r, t.TempDir())
	var checker *security.Checker
	if provider != nil {
		checker = security.NewChecker(provider, nil)
	}
	pipe := pipeline.New(disc, checker)

	m := NewModel(nil, mode)
	m.SetInitCmd(m.StartPipeline(pipe, false))
	return m, m.Init()
}

// --- The loading screen must hand off to the list ---

func TestPipelineDrivesLoadingToList(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/a", "v1.0.0", "v1.1.0") + "\n" +
		goListJSON("github.com/b", "v2.0.0", "v2.1.0")}

	m, cmd := startModel(t, r, &stubProvider{}, SecurityOn)
	if m.screen != screenLoading {
		t.Fatalf("model should start loading, got %v", m.screen)
	}

	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("pipeline must hand off to the list screen, got %v", m.screen)
	}
	if len(m.visible) != 2 {
		t.Errorf("expected both dependencies listed, got %d", len(m.visible))
	}
	view := m.View()
	for _, want := range []string{"github.com/a", "github.com/b"} {
		if !strings.Contains(view, want) {
			t.Errorf("list view missing %q: %q", want, view)
		}
	}
}

func TestPipelineProgressReachesTheModel(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/a", "v1.0.0", "v1.1.0")}
	m, cmd := startModel(t, r, &stubProvider{}, SecurityOn)

	runProgram(t, m, cmd, 5*time.Second)

	// Reaching the list at all proves the reader kept draining the stream:
	// the result is only ever delivered after the progress events, so a
	// reader that stopped at the first event would strand the UI loading.
	if m.screen != screenList {
		t.Fatalf("expected the list after the full stream, got %v", m.screen)
	}
	if len(m.visible) != 1 {
		t.Errorf("expected 1 dependency listed, got %d", len(m.visible))
	}
}

// TestProgressMessageReArmsReader pins the fix for the stranded loading
// screen: a progress message must hand back a command that keeps reading.
// Without it the UI consumes the first progress event and waits forever.
func TestProgressMessageReArmsReader(t *testing.T) {
	m := NewModel(nil, SecurityOn)
	m.pipelineMsgs = make(chan tea.Msg, 1) // non-nil, as StartPipeline leaves it

	_, cmd := m.Update(pipelineProgressMsg{progress: pipeline.Progress{
		Stage: pipeline.StageSecurity, Done: 3, Total: 7, Module: "github.com/a",
	}})

	if cmd == nil {
		t.Fatal("a progress message must re-arm the pipeline reader")
	}
	if m.loadingStage != pipeline.StageSecurity || m.loadingDone != 3 || m.loadingTotal != 7 {
		t.Errorf("progress not applied: stage=%v done=%d total=%d",
			m.loadingStage, m.loadingDone, m.loadingTotal)
	}
}

func TestPipelineFatalErrorShowsErrorScreen(t *testing.T) {
	r := &listRunner{err: errors.New("go: command not found")}
	m, cmd := startModel(t, r, &stubProvider{}, SecurityOn)

	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenError {
		t.Fatalf("fatal discovery failure should show the error screen, got %v", m.screen)
	}
	if !strings.Contains(m.View(), "command not found") {
		t.Errorf("error view should carry the reason: %q", m.View())
	}
}

func TestPipelineSecurityStatusesApplied(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/vuln", "v1.0.0", "v1.1.0") + "\n" +
		goListJSON("github.com/clean", "v1.0.0", "v1.1.0")}
	provider := &stubProvider{vulns: map[string][]security.Vulnerability{
		"github.com/vuln": {{ID: "GO-2026-1", Severity: security.SeverityCritical}},
	}}

	m, cmd := startModel(t, r, provider, SecurityOn)
	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	if !m.hasSecurityData() {
		t.Fatal("security statuses should be aligned with the deps")
	}
	// Discovery orders by path, so the vulnerable dep may not be deps[0];
	// what matters is that it sorts first on screen.
	if got := m.deps[m.visible[0]].Path; got != "github.com/vuln" {
		t.Errorf("vulnerable dependency should sort first, got %q (visible=%v)", got, m.visible)
	}
	view := m.View()
	if !strings.Contains(view, "CRITICAL") {
		t.Errorf("severity badge missing from the list: %q", view)
	}
}

func TestPipelineSecurityDisabledByFlag(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/a", "v1.0.0", "v1.1.0")}
	// No checker: the pipeline reports security disabled.
	m, cmd := startModel(t, r, nil, SecurityOn)

	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	if m.secMode != SecurityOff {
		t.Errorf("mode = %v, want SecurityOff after a disabled result", m.secMode)
	}
	if m.hasSecurityData() {
		t.Error("no security data should be present")
	}
	if !strings.Contains(m.View(), "security check disabled") {
		t.Errorf("disabled notice missing: %q", m.View())
	}
}

// --- Security-only mode (--security) ---

func TestPipelineSecurityOnlyFiltersAndReports(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/vuln", "v1.0.0", "v1.1.0") + "\n" +
		goListJSON("github.com/clean", "v1.0.0", "v1.1.0")}
	provider := &stubProvider{vulns: map[string][]security.Vulnerability{
		"github.com/vuln": {{ID: "GO-2026-1", Severity: security.SeverityHigh}},
	}}

	m, cmd := startModel(t, r, provider, SecurityOnly)
	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	if len(m.visible) != 1 || m.deps[m.visible[0]].Path != "github.com/vuln" {
		t.Fatalf("security-only should list just the vulnerable dep, got %v", m.visible)
	}
	view := m.View()
	if !strings.Contains(view, "1 vulnerable dependency") {
		t.Errorf("security-only subtitle missing: %q", view)
	}
	if strings.Contains(view, "github.com/clean") {
		t.Errorf("clean dependency must not be listed: %q", view)
	}
}

func TestPipelineSecurityOnlyWithNothingVulnerable(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/clean", "v1.0.0", "v1.1.0")}
	m, cmd := startModel(t, r, &stubProvider{}, SecurityOnly)

	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "No vulnerable dependencies") {
		t.Errorf("a clean security-only run should say so, got: %q", view)
	}
}

// TestSecurityOnlyDoesNotClaimCleanWhenChecksFailed guards the honesty rule
// for the filtered view: failed checks are excluded from the vulnerable
// list, so an empty --security list must not read as a clean bill of health
// when the database was unreachable.
func TestSecurityOnlyDoesNotClaimCleanWhenChecksFailed(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/a", "v1.0.0", "v1.1.0")}
	provider := &stubProvider{err: errors.New("network unreachable")}

	m, cmd := startModel(t, r, provider, SecurityOnly)
	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	view := m.View()
	if strings.Contains(view, "No vulnerable dependencies") {
		t.Errorf("must not claim a clean result when the check failed: %q", view)
	}
	if !strings.Contains(view, "could not be checked") {
		t.Errorf("should surface the unchecked dependencies: %q", view)
	}
}

// --- The security detail screen must render through View ---

func TestDetailScreenRendersThroughView(t *testing.T) {
	deps := []module.Dependency{
		{Path: "github.com/vuln", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	items := []security.DependencyStatus{ds(deps[0], vulnStatus(testVulnHigh), security.FixResolved)}
	m := newModelWithSecurity(deps, items, SecurityOn)

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if m.screen != screenDetail {
		t.Fatalf("d should open the detail screen, got %v", m.screen)
	}

	view := m.View()
	if view == "" {
		t.Fatal("View() returned nothing for the detail screen")
	}
	for _, want := range []string{"Security details", "github.com/vuln", "GO-2026-1111"} {
		if !strings.Contains(view, want) {
			t.Errorf("detail view missing %q: %q", want, view)
		}
	}

	// Esc returns to the list, which must render again.
	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.screen != screenList {
		t.Fatalf("esc should return to the list, got %v", m.screen)
	}
	if m.View() == "" {
		t.Error("list view empty after returning from the detail screen")
	}
}

// --- "d" must be inert when there is no security data ---

func TestDetailKeyInertWithoutSecurityData(t *testing.T) {
	// --no-security: the check never ran, so there is nothing to detail.
	m, cmd := startModel(t,
		&listRunner{output: goListJSON("github.com/a", "v1.0.0", "v1.1.0")},
		nil, SecurityOff)
	runProgram(t, m, cmd, 5*time.Second)

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if m.screen != screenList {
		t.Errorf("d must not open the detail screen without security data, got %v", m.screen)
	}

	// The hint is hidden too.
	if strings.Contains(m.View(), "Security details") {
		t.Errorf("help bar should not advertise security details: %q", m.View())
	}

	// And the defensive render guard must not panic if reached directly.
	m.detailIndex = 0
	if got := m.detailView(); !strings.Contains(got, "No security information") {
		t.Errorf("detailView should degrade gracefully, got: %q", got)
	}
}

// --- Skipped modules survive the async path ---

func TestPipelineCarriesSkippedModules(t *testing.T) {
	r := &listRunner{output: goListJSON("github.com/ok", "v1.0.0", "v1.1.0") + "\n" +
		`{"path":"github.com/broken","error":{"Err":"cannot find module"}}`}
	m, cmd := startModel(t, r, &stubProvider{}, SecurityOn)

	runProgram(t, m, cmd, 5*time.Second)

	if m.screen != screenList {
		t.Fatalf("expected the list screen, got %v", m.screen)
	}
	if len(m.skipped) != 1 || m.skipped[0].Path != "github.com/broken" {
		t.Fatalf("skipped module should reach the model, got %+v", m.skipped)
	}
	view := m.View()
	if !strings.Contains(view, "1 dependencies skipped") {
		t.Errorf("skipped count missing from the list: %q", view)
	}

	// "s" opens the reasons, and Esc comes back.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if m.screen != screenSkipped {
		t.Fatalf("s should open the skipped view, got %v", m.screen)
	}
	if !strings.Contains(m.View(), "cannot find module") {
		t.Errorf("skipped view should show the reason: %q", m.View())
	}
}

// --- Every screen must render something ---

func TestEveryScreenRendersNonEmpty(t *testing.T) {
	deps := []module.Dependency{{Path: "github.com/a", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"}}
	items := []security.DependencyStatus{ds(deps[0], vulnStatus(testVulnHigh), security.FixResolved)}

	screens := map[string]screen{
		"loading":   screenLoading,
		"list":      screenList,
		"skipped":   screenSkipped,
		"detail":    screenDetail,
		"confirm":   screenConfirm,
		"upgrading": screenUpgrading,
		"done":      screenDone,
		"error":     screenError,
	}
	for name, s := range screens {
		t.Run(name, func(t *testing.T) {
			m := newModelWithSecurity(deps, items, SecurityOn)
			m.screen = s
			m.confirmDeps = []int{0}
			m.upgradeTotal = 1
			if got := m.View(); got == "" {
				t.Errorf("screen %v rendered an empty view", s)
			}
		})
	}
}

var _ runner.CommandRunner = (*listRunner)(nil)
var _ security.Provider = (*stubProvider)(nil)
