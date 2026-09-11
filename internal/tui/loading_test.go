package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/pipeline"
	"github.com/kianooshaz/goup/internal/security"
)

// --- Loading screen ---

func TestNewModelStartsInLoadingState(t *testing.T) {
	m := NewModel(nil, SecurityOn)

	if m.screen != screenLoading {
		t.Fatalf("NewModel should start on the loading screen, got %v", m.screen)
	}
	if cmd := m.Init(); cmd == nil {
		t.Error("loading model must return a spinner command from Init")
	}
	view := m.View()
	if !strings.Contains(view, "Discovering dependencies...") {
		t.Errorf("loading view should show spinner and operation: %q", view)
	}
}

func TestLoadingViewShowsCurrentOperation(t *testing.T) {
	m := NewModel(nil, SecurityOn)

	// Reading stage.
	m.Update(pipelineProgressMsg{progress: pipeline.Progress{Stage: pipeline.StageReading}})
	view := m.View()
	if !strings.Contains(view, "Discovering dependencies...") {
		t.Errorf("reading stage missing: %q", view)
	}

	// Security stage with a module name and numeric progress.
	m.Update(pipelineProgressMsg{progress: pipeline.Progress{
		Stage: pipeline.StageSecurity, Module: "github.com/gin-gonic/gin", Done: 8, Total: 24,
	}})
	view = m.View()
	if !strings.Contains(view, "Checking github.com/gin-gonic/gin") {
		t.Errorf("module being checked missing: %q", view)
	}
	if !strings.Contains(view, "8 of 24") {
		t.Errorf("numeric progress missing: %q", view)
	}
}

func TestLoadingViewStaysResponsive(t *testing.T) {
	m := NewModel(nil, SecurityOn)

	// Keys other than quit are ignored but the model keeps working.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if m.screen != screenLoading {
		t.Errorf("random keys must not disturb loading, screen = %v", m.screen)
	}

	// Quit works during loading.
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Error("esc must quit during loading")
	}
}

// --- Applying the pipeline result ---

func loadingTestModel() *Model {
	return NewModel(nil, SecurityOn)
}

func TestApplyResultTransitionsToList(t *testing.T) {
	m := loadingTestModel()

	deps := []module.Dependency{
		{Path: "github.com/a", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/b", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	m.Update(pipelineResultMsg{result: pipeline.Result{Dependencies: deps}})

	if m.screen != screenList {
		t.Fatalf("result should switch to the list, screen = %v", m.screen)
	}
	if len(m.visible) != 2 {
		t.Errorf("list should show the discovered deps, got %d", len(m.visible))
	}
	if !strings.Contains(m.View(), "github.com/a") {
		t.Error("list should render discovered dependencies")
	}
}

func TestApplyResultWithErrorScreen(t *testing.T) {
	m := loadingTestModel()
	m.Update(pipelineErrMsg{err: errors.New("go list failed")})

	if m.screen != screenError {
		t.Fatalf("fatal error should show error screen, got %v", m.screen)
	}
	if !strings.Contains(m.View(), "go list failed") {
		t.Error("error view should include the reason")
	}
}

func TestApplyResultWithSecurityData(t *testing.T) {
	m := loadingTestModel()

	deps := []module.Dependency{
		{Path: "github.com/vuln", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	items := securityItemsFor(deps, "github.com/vuln")
	m.Update(pipelineResultMsg{result: pipeline.Result{Dependencies: deps, Security: items}})

	if len(m.security) != 1 || m.security[0].Status.Severity != security.SeverityHigh {
		t.Errorf("security statuses should be applied: %+v", m.security)
	}
	// Security-first ordering and badges work as usual after async load.
	view := m.View()
	if !strings.Contains(view, "HIGH") {
		t.Error("badges should render after async discovery")
	}
}

func TestApplyResultDisabledSecurity(t *testing.T) {
	m := NewModel(nil, SecurityOn) // requested on, but pipeline disabled it
	deps := []module.Dependency{{Path: "github.com/a", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"}}
	m.Update(pipelineResultMsg{result: pipeline.Result{Dependencies: deps, SecurityDisabled: true}})

	if m.secMode != SecurityOff {
		t.Errorf("disabled result should switch mode to off, got %v", m.secMode)
	}
}

// --- Skipped dependencies tracking ---

func TestSkippedCountShownOnList(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.skipped = []module.SkippedDependency{
		{Path: "github.com/broken", Reason: errors.New("failed to fetch version information")},
		{Path: "github.com/slow", Reason: errors.New("network timeout")},
	}

	view := m.View()
	if !strings.Contains(view, "2 dependencies skipped") {
		t.Errorf("skipped count missing from list header/footer: %q", view)
	}
	if !strings.Contains(view, "s for details") {
		t.Errorf("detail hint missing: %q", view)
	}
}

func TestSkippedDetailView(t *testing.T) {
	m := newSearchModel("github.com/a")
	m.skipped = []module.SkippedDependency{
		{Path: "github.com/example/foo", Reason: errors.New("failed to fetch version information")},
		{Path: "github.com/example/bar", Reason: errors.New("network timeout")},
	}

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if m.screen != screenSkipped {
		t.Fatalf("s should open the skipped view, screen = %v", m.screen)
	}

	view := m.View()
	for _, want := range []string{
		"Skipped dependencies",
		"github.com/example/foo",
		"failed to fetch version information",
		"github.com/example/bar",
		"network timeout",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("skipped view missing %q", want)
		}
	}

	// Esc returns to the list.
	m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	if m.screen != screenList {
		t.Errorf("esc should return to list, screen = %v", m.screen)
	}
}

func TestSkippedKeyHiddenWhenNothingSkipped(t *testing.T) {
	m := newSearchModel("github.com/a")
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if m.screen == screenSkipped {
		t.Error("s must not open the skipped view when nothing was skipped")
	}
}

// --- Empty results after async discovery ---

func TestUpToDateMessageAfterDiscovery(t *testing.T) {
	m := loadingTestModel()
	m.Update(pipelineResultMsg{result: pipeline.Result{Dependencies: nil}})

	if m.screen != screenList {
		t.Fatalf("should land on the list, screen = %v", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "up to date") {
		t.Errorf("empty list should say everything is up to date: %q", view)
	}
}

// --- Spinner keep-alive on the loading screen ---

func TestSpinnerTicksOnlyWhileLoading(t *testing.T) {
	m := loadingTestModel()

	_, cmd := m.Update(spinner.TickMsg{})
	if cmd == nil {
		t.Error("spinner should keep ticking on the loading screen")
	}

	// After the result arrives, ticks stop re-arming.
	m.Update(pipelineResultMsg{result: pipeline.Result{
		Dependencies: []module.Dependency{{Path: "github.com/a", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"}},
	}})
	_, cmd = m.Update(spinner.TickMsg{})
	if cmd != nil {
		t.Error("spinner should not tick after loading finished")
	}
}
