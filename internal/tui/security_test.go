package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/security"
)

func ds(dep module.Dependency, status security.Status, fix security.FixAssessment) security.DependencyStatus {
	return security.DependencyStatus{Dependency: dep, Status: status, Fix: fix}
}

func cleanStatus() security.Status {
	return security.Status{Checked: true, Severity: security.SeverityNone}
}

func vulnStatus(vulns ...security.Vulnerability) security.Status {
	// Compute the worst severity the same way the checker does.
	worst := security.SeverityUnknown
	for _, v := range vulns {
		if v.Severity.Rank() > worst.Rank() {
			worst = v.Severity
		}
	}
	return security.Status{
		Checked:         true,
		Severity:        worst,
		Vulnerabilities: vulns,
	}
}

var (
	testVulnHigh   = security.Vulnerability{ID: "GO-2026-1111", Severity: security.SeverityHigh, FixedIn: "v1.4.5", Summary: "bad thing"}
	testVulnNoFix  = security.Vulnerability{ID: "GO-2026-2222", Severity: security.SeverityHigh}
	testVulnMedium = security.Vulnerability{ID: "GHSA-aaaa-bbbb-cccc", Severity: security.SeverityMedium, FixedIn: "v1.2.3"}
)

// --- Row rendering states ---

func TestSecurityColumnStates(t *testing.T) {
	dep := module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.4.2", LatestVersion: "v1.5.0"}

	tests := []struct {
		name     string
		item     security.DependencyStatus
		contains []string
	}{
		{
			name:     "vulnerable shows badge",
			item:     ds(dep, vulnStatus(testVulnHigh), security.FixResolved),
			contains: []string{"HIGH", "🟠"},
		},
		{
			name:     "critical shows red badge",
			item:     ds(dep, vulnStatus(security.Vulnerability{ID: "X", Severity: security.SeverityCritical, FixedIn: "v2"}), security.FixResolved),
			contains: []string{"CRITICAL", "🔴"},
		},
		{
			name:     "multiple vulnerabilities show count",
			item:     ds(dep, vulnStatus(testVulnHigh, testVulnMedium, testVulnNoFix), security.FixResolved),
			contains: []string{"HIGH (3)"},
		},
		{
			name:     "clean shows checkmark",
			item:     ds(dep, cleanStatus(), security.FixUnknown),
			contains: []string{"✓"},
		},
		{
			name:     "failed check never looks clean",
			item:     ds(dep, security.Status{Checked: false, Err: errors.New("boom")}, security.FixUnknown),
			contains: []string{"⚠", "security check failed"},
		},
		{
			name: "unknown severity shown explicitly",
			item: ds(dep, security.Status{Checked: true, Severity: security.SeverityUnknown,
				Vulnerabilities: []security.Vulnerability{{ID: "X", Severity: security.SeverityUnknown}}}, security.FixResolved),
			contains: []string{"UNKNOWN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := securityColumn(tt.item)
			for _, want := range tt.contains {
				if !strings.Contains(got, want) {
					t.Errorf("securityColumn() = %q, want substring %q", got, want)
				}
			}
		})
	}

	// A failed check must not contain the clean checkmark.
	failed := securityColumn(ds(dep, security.Status{Checked: false, Err: errors.New("x")}, security.FixUnknown))
	if strings.Contains(failed, "✓ NO KNOWN ISSUES") || strings.Contains(failed, "✓ NO") {
		t.Errorf("failed check rendered as clean: %q", failed)
	}
}

func TestFixNoteStates(t *testing.T) {
	dep := module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5"}

	tests := []struct {
		fix  security.FixAssessment
		want string
	}{
		{security.FixResolved, "fixed by upgrade"},
		{security.FixPartial, "partially fixed"},
		{security.FixUnresolved, "does not fix"},
		{security.FixNoneAvailable, "no fix available"},
		{security.FixUnknown, ""},
	}
	for _, tt := range tests {
		got := fixNote(ds(dep, vulnStatus(testVulnHigh), tt.fix))
		if tt.want == "" {
			if got != "" {
				t.Errorf("fixNote(%v) = %q, want empty", tt.fix, got)
			}
			continue
		}
		if !strings.Contains(got, tt.want) {
			t.Errorf("fixNote(%v) = %q, want substring %q", tt.fix, got, tt.want)
		}
	}

	// Clean dependencies get no note.
	if got := fixNote(ds(dep, cleanStatus(), security.FixUnknown)); got != "" {
		t.Errorf("clean dep should have no fix note, got %q", got)
	}
}

// --- Summary rendering ---

func TestSummarizeAndRender(t *testing.T) {
	deps := []security.DependencyStatus{
		ds(module.Dependency{Path: "a"},
			vulnStatus(security.Vulnerability{ID: "1", Severity: security.SeverityCritical, FixedIn: "v2"}),
			security.FixResolved),
		ds(module.Dependency{Path: "b"},
			vulnStatus(security.Vulnerability{ID: "2", Severity: security.SeverityHigh, FixedIn: "v2"}),
			security.FixResolved),
		ds(module.Dependency{Path: "c"}, cleanStatus(), security.FixUnknown),
		ds(module.Dependency{Path: "d"},
			security.Status{Checked: false, Err: errors.New("offline")}, security.FixUnknown),
	}

	s := Summarize(deps)
	if s.TotalVulnerable != 2 {
		t.Errorf("TotalVulnerable = %d, want 2", s.TotalVulnerable)
	}
	if s.BySeverity[security.SeverityCritical] != 1 || s.BySeverity[security.SeverityHigh] != 1 {
		t.Errorf("BySeverity wrong: %+v", s.BySeverity)
	}
	if s.FailedChecks != 1 {
		t.Errorf("FailedChecks = %d, want 1", s.FailedChecks)
	}

	rendered := s.Render()
	if !strings.Contains(rendered, "2 security fixes") {
		t.Errorf("render missing count: %q", rendered)
	}
	if !strings.Contains(rendered, "could not be checked") {
		t.Errorf("render missing failed-check warning: %q", rendered)
	}

	// All-clean summary renders empty.
	allClean := Summarize([]security.DependencyStatus{
		ds(module.Dependency{Path: "x"}, cleanStatus(), security.FixUnknown),
	})
	if allClean.HasIssues() || allClean.Render() != "" {
		t.Errorf("clean summary should render empty, got %q", allClean.Render())
	}

	// Severity breakdown line: 1 critical + 1 high.
	renderedBreakdown := s.Render()
	if !strings.Contains(renderedBreakdown, "🔴 1") || !strings.Contains(renderedBreakdown, "🟠 1") {
		t.Errorf("render missing per-severity counts: %q", renderedBreakdown)
	}
}

// --- Detail view content ---

func newDetailModel(items []security.DependencyStatus) *Model {
	deps := make([]module.Dependency, len(items))
	for i, it := range items {
		deps[i] = it.Dependency
	}
	m := NewModel(deps, items, SecurityOn, nil)
	m.width = 100
	return m
}

func TestDetailViewResolved(t *testing.T) {
	items := []security.DependencyStatus{
		ds(module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5"},
			vulnStatus(testVulnHigh), security.FixResolved),
	}
	m := newDetailModel(items)
	m.detailIndex = 0
	m.screen = screenDetail

	view := m.detailView()
	for _, want := range []string{
		"Security details",
		"github.com/foo/bar",
		"v1.4.2",
		"GO-2026-1111",
		"Fixed in:",
		"v1.4.5",
		"resolves the known vulnerabilities",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("detail view missing %q", want)
		}
	}
}

func TestDetailViewNoFixAvailable(t *testing.T) {
	items := []security.DependencyStatus{
		ds(module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
			vulnStatus(testVulnNoFix), security.FixNoneAvailable),
	}
	m := newDetailModel(items)
	m.detailIndex = 0
	m.screen = screenDetail

	if !strings.Contains(m.detailView(), "No fixed version is known") {
		t.Error("detail view should state that no fix is known")
	}
}

func TestDetailViewUnavailable(t *testing.T) {
	items := []security.DependencyStatus{
		ds(module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
			security.Status{Checked: false, Err: errors.New("timeout")}, security.FixUnknown),
	}
	m := newDetailModel(items)
	m.detailIndex = 0
	m.screen = screenDetail

	view := m.detailView()
	if !strings.Contains(view, "unavailable") || !strings.Contains(view, "timeout") {
		t.Errorf("detail view should show unavailability with reason, got %q", view)
	}
	if strings.Contains(view, "No known vulnerabilities") {
		t.Error("failed check must not render as 'no known vulnerabilities'")
	}
}

func TestDetailViewClean(t *testing.T) {
	items := []security.DependencyStatus{
		ds(module.Dependency{Path: "github.com/foo/bar", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
			cleanStatus(), security.FixUnknown),
	}
	m := newDetailModel(items)
	m.detailIndex = 0
	m.screen = screenDetail

	if !strings.Contains(m.detailView(), "No known vulnerabilities") {
		t.Error("clean dependency should show the all-clear line")
	}
}

// --- List view: security-first ordering and security-only filtering ---

func TestListViewSecurityFirstOrdering(t *testing.T) {
	deps := []module.Dependency{
		{Path: "github.com/foo/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/vuln", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5"},
	}
	items := []security.DependencyStatus{
		ds(deps[0], cleanStatus(), security.FixUnknown),
		ds(deps[1], vulnStatus(testVulnHigh), security.FixResolved),
	}

	m := NewModel(deps, items, SecurityOn, nil)
	// Vulnerable dependency must be listed first.
	if got := m.visible[0]; got != 1 {
		t.Errorf("first visible = deps[%d] (%s), want the vulnerable dep",
			got, deps[got].Path)
	}

	view := m.listView()
	if !strings.Contains(view, "1 security fixes") {
		t.Errorf("list header missing security summary: %q", view)
	}
	if !strings.Contains(view, "HIGH") {
		t.Errorf("list missing severity badge: %q", view)
	}
}

func TestListViewSecurityOnlyFilter(t *testing.T) {
	deps := []module.Dependency{
		{Path: "github.com/foo/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/vuln", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5"},
	}
	items := []security.DependencyStatus{
		ds(deps[0], cleanStatus(), security.FixUnknown),
		ds(deps[1], vulnStatus(testVulnHigh), security.FixResolved),
	}

	m := NewModel(deps, items, SecurityOnly, nil)
	if len(m.visible) != 1 || m.visible[0] != 1 {
		t.Fatalf("security-only mode should list only the vulnerable dep, got %+v", m.visible)
	}

	view := m.listView()
	if strings.Contains(view, "github.com/foo/clean") {
		t.Error("security-only view must hide clean dependencies")
	}
	if !strings.Contains(view, "github.com/foo/vuln") {
		t.Error("security-only view must show the vulnerable dependency")
	}
}

func TestListViewSecurityOff(t *testing.T) {
	deps := []module.Dependency{
		{Path: "github.com/foo/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/vuln", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5"},
	}
	items := []security.DependencyStatus{
		ds(deps[0], cleanStatus(), security.FixUnknown),
		ds(deps[1], vulnStatus(testVulnHigh), security.FixResolved),
	}

	m := NewModel(deps, items, SecurityOff, nil)
	if len(m.visible) != 2 {
		t.Fatalf("security-off shows all deps, got %d", len(m.visible))
	}
	// Original discovery order preserved (clean first, since no re-sort).
	if m.visible[0] != 0 || m.visible[1] != 1 {
		t.Errorf("security-off must preserve discovery order, got %+v", m.visible)
	}

	view := m.listView()
	if strings.Contains(view, "HIGH") || strings.Contains(view, "Security") {
		t.Error("security-off view must not render security columns")
	}
}

func TestSecurityForIndexOutOfRange(t *testing.T) {
	m := NewModel(nil, nil, SecurityOn, nil)
	got := m.securityFor(5)
	if got.Status.Checked || got.Dependency.Path != "" {
		t.Errorf("out-of-range securityFor should return zero value, got %+v", got)
	}
}

// --- wrapText ---

func TestWrapText(t *testing.T) {
	long := "A vulnerability allows remote attackers to execute arbitrary code via crafted input files"
	wrapped := wrapText(long, 60, 4)
	lines := strings.Split(wrapped, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected wrapped output, got %q", wrapped)
	}
	for i, l := range lines {
		if i > 0 && !strings.HasPrefix(l, "    ") {
			t.Errorf("continuation line not indented: %q", l)
		}
		if len(l) > 60 {
			t.Errorf("line exceeds width: %q", l)
		}
	}
}
