package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/security"
)

// newSearchModel builds a model with the given module paths and no
// security data, ready for list-screen interaction.
func newSearchModel(paths ...string) *Model {
	deps := make([]module.Dependency, len(paths))
	for i, p := range paths {
		deps[i] = module.Dependency{Path: p, CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"}
	}
	return NewModel(deps, nil, SecurityOff, nil)
}

func key(s string) tea.KeyMsg {
	if len([]rune(s)) == 1 {
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
	switch s {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEscape}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func visiblePaths(m *Model) []string {
	out := make([]string, len(m.visible))
	for i, idx := range m.visible {
		out[i] = m.deps[idx].Path
	}
	return out
}

func joinPaths(m *Model) string {
	return strings.Join(visiblePaths(m), ",")
}

// --- Entering and exiting search mode ---

func TestEnterSearchWithSlash(t *testing.T) {
	m := newSearchModel("github.com/a", "golang.org/x/net")
	m.handleListKey(key("/"))

	if !m.searching {
		t.Fatal("/ should enter search mode")
	}
	if len(m.visible) != 2 {
		t.Errorf("empty query must show all deps, got %d", len(m.visible))
	}
	// The view shows the search input.
	if !strings.Contains(m.listView(), "Search:") {
		t.Error("list view should render the search input line")
	}
}

func TestEscClearsAndExitsSearch(t *testing.T) {
	m := newSearchModel("github.com/a", "golang.org/x/net")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("a"))

	m.handleSearchKey(key("esc"))

	if m.searching || m.query != "" {
		t.Fatalf("esc must clear query and exit: searching=%v query=%q", m.searching, m.query)
	}
	if len(m.visible) != 2 {
		t.Errorf("clearing search must restore the full list, got %d", len(m.visible))
	}
}

func TestEnterExitsSearchKeepingFilter(t *testing.T) {
	m := newSearchModel("github.com/a", "golang.org/x/net")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("x"))

	m.handleSearchKey(key("enter"))

	if m.searching {
		t.Error("enter should exit search mode")
	}
	if m.query != "x" {
		t.Errorf("enter should keep the filter, query = %q", m.query)
	}
	if len(m.visible) != 1 {
		t.Errorf("filter should still apply after enter, got %d visible", len(m.visible))
	}
}

// --- Matching behavior ---

func TestSearchCaseInsensitive(t *testing.T) {
	m := newSearchModel("golang.org/x/net", "golang.org/x/sync", "github.com/gin-gonic/gin")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("GOLANG.ORG/X"))

	if got := len(m.visible); got != 2 {
		t.Fatalf("uppercase query matched %d deps, want 2: %s", got, joinPaths(m))
	}
}

func TestSearchSubstring(t *testing.T) {
	m := newSearchModel("github.com/redis/go-redis/v9", "github.com/foo/bar")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("redis"))

	if len(m.visible) != 1 || m.deps[m.visible[0]].Path != "github.com/redis/go-redis/v9" {
		t.Errorf("substring search failed: %s", joinPaths(m))
	}
}

func TestSearchPathSegment(t *testing.T) {
	m := newSearchModel("golang.org/x/sync", "golang.org/x/net", "github.com/x/other")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("x/sync"))

	if len(m.visible) != 1 || m.deps[m.visible[0]].Path != "golang.org/x/sync" {
		t.Errorf("x/sync should match only golang.org/x/sync: %s", joinPaths(m))
	}
}

func TestSearchExactMatchRanksFirst(t *testing.T) {
	m := newSearchModel("github.com/foo/redis-wrapper", "github.com/redis/go-redis/v9")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("redis"))

	// Both match as substrings, but the path whose segment starts with the
	// query ranks first.
	if m.deps[m.visible[0]].Path != "github.com/redis/go-redis/v9" {
		t.Errorf("prefix match should rank first: %s", joinPaths(m))
	}
}

func TestSearchNoResults(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("does-not-exist"))

	if len(m.visible) != 0 {
		t.Fatalf("expected no matches, got %s", joinPaths(m))
	}
	view := m.listView()
	if !strings.Contains(view, "No dependencies found.") {
		t.Errorf("no-results view missing: %q", view)
	}
	if !strings.Contains(view, "Clear search") {
		t.Errorf("no-results view should offer Esc: %q", view)
	}
	// App must remain alive and usable.
	if m.screen != screenList {
		t.Errorf("no results must not change screens, screen = %v", m.screen)
	}
	m.handleSearchKey(key("esc"))
	if len(m.visible) != 2 {
		t.Errorf("esc after no results must restore list, got %d", len(m.visible))
	}
}

func TestSearchEmptyQueryShowsAll(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b", "github.com/c")
	m.handleListKey(key("/"))

	if len(m.visible) != 3 {
		t.Errorf("empty query must show all, got %d", len(m.visible))
	}
}

func TestSearchMultipleResults(t *testing.T) {
	m := newSearchModel("golang.org/x/net", "golang.org/x/sync", "golang.org/x/text", "github.com/gin-gonic/gin")
	m.handleListKey(key("/"))
	for _, c := range "golang.org/x" {
		m.handleSearchKey(key(string(c)))
	}

	if len(m.visible) != 3 {
		t.Fatalf("expected 3 matches, got %s", joinPaths(m))
	}
	view := m.listView()
	if !strings.Contains(view, "3 of 4 dependencies match") {
		t.Errorf("match count missing from view: %q", view)
	}
}

// --- Keyboard behavior in search mode ---

func TestSearchModeTypingQDoesNotQuit(t *testing.T) {
	m := newSearchModel("github.com/qmq", "github.com/other")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("q"))

	if m.query != "q" {
		t.Errorf("q must be inserted into the query, got %q", m.query)
	}
	// Model still active — only esc/ctrl+c can quit from here, and the
	// filtered list contains the match.
	if len(m.visible) != 1 {
		t.Errorf("expected the q match, got %s", joinPaths(m))
	}
}

func TestSearchModeSelectAllNoneAreText(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("a"))
	m.handleSearchKey(key("n"))

	if m.query != "an" {
		t.Errorf("a/n must insert as text in search mode, query = %q", m.query)
	}
}

func TestSearchModeNavigationKeys(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b", "github.com/c")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("down"))
	m.handleSearchKey(key("down"))

	if m.cursor != 2 {
		t.Errorf("down should move the cursor in search mode, cursor = %d", m.cursor)
	}
	m.handleSearchKey(key("up"))
	if m.cursor != 1 {
		t.Errorf("up should move the cursor in search mode, cursor = %d", m.cursor)
	}
}

func TestSearchBackspaceRemovesCharacter(t *testing.T) {
	m := newSearchModel("github.com/net", "github.com/sync")
	m.handleListKey(key("/"))
	for _, c := range "netx" {
		m.handleSearchKey(key(string(c)))
	}
	m.handleSearchKey(key("backspace"))

	if m.query != "net" {
		t.Fatalf("backspace should remove last char, query = %q", m.query)
	}
	if len(m.visible) != 1 {
		t.Errorf("filter should update live on backspace, got %s", joinPaths(m))
	}
}

func TestSearchLiveFilteringPerKeystroke(t *testing.T) {
	m := newSearchModel("golang.org/x/net", "golang.org/x/sync", "github.com/gin")
	m.handleListKey(key("/"))

	for _, c := range "golang" {
		m.handleSearchKey(key(string(c)))
	}
	if len(m.visible) != 2 {
		t.Errorf("live filter after 'golang': %s", joinPaths(m))
	}
	for _, c := range ".org/x/net" {
		m.handleSearchKey(key(string(c)))
	}
	if len(m.visible) != 1 || m.deps[m.visible[0]].Path != "golang.org/x/net" {
		t.Errorf("live filter after full query: %s", joinPaths(m))
	}
}

func TestSearchSpaceTogglesSelectionNotQuery(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.handleListKey(key("/"))
	m.handleSearchKey(key(" ")) // toggle row 0

	if m.query != "" {
		t.Errorf("space should not alter the query, query = %q", m.query)
	}
	if !m.selected[0] {
		t.Error("space should toggle selection while searching")
	}
}

// --- Selection persistence ---

func TestSelectionSurvivesSearchRoundTrip(t *testing.T) {
	m := newSearchModel("pkg-alpha", "pkg-beta", "pkg-gamma", "pkg-delta")
	m.handleListKey(key(" "))    // select alpha
	m.handleListKey(key("down")) // beta
	m.handleListKey(key(" "))    // select beta
	m.handleListKey(key("down")) // gamma
	m.handleListKey(key(" "))    // select gamma

	// Search filters to a subset.
	m.handleListKey(key("/"))
	for _, c := range "gamma" {
		m.handleSearchKey(key(string(c)))
	}
	if len(m.visible) != 1 {
		t.Fatalf("search should isolate pkg-gamma, got %s", joinPaths(m))
	}

	// Modify selection within the filtered view: select pkg-delta, which
	// was not selected before.
	m.handleSearchKey(key("esc"))
	m.handleListKey(key("/"))
	for _, c := range "delta" {
		m.handleSearchKey(key(string(c)))
	}
	m.handleSearchKey(key(" ")) // select delta

	// Clear search: previous selections must be intact.
	m.handleSearchKey(key("esc"))
	if m.query != "" || m.searching {
		t.Fatal("search should be cleared")
	}
	if len(m.visible) != 4 {
		t.Fatalf("full list should be restored, got %s", joinPaths(m))
	}
	if !m.selected[0] {
		t.Error("selection on pkg-alpha lost across filtering")
	}
	if !m.selected[1] {
		t.Error("selection on pkg-beta lost across filtering")
	}
	if !m.selected[2] {
		t.Error("selection on pkg-gamma lost across filtering")
	}
	if !m.selected[3] {
		t.Error("selection made inside filtered view not persisted")
	}
}

func TestSelectionKeyedByDependencyNotPosition(t *testing.T) {
	m := newSearchModel("github.com/aaa", "github.com/bbb", "github.com/ccc")
	m.handleListKey(key("/"))
	for _, c := range "bbb" {
		m.handleSearchKey(key(string(c)))
	}
	m.handleSearchKey(key(" ")) // selects the only visible row (deps[1])

	m.handleSearchKey(key("esc"))
	// After clearing, bbb may no longer be at row 1 — selection must
	// still point at the dependency.
	found := false
	for i, idx := range m.visible {
		if m.deps[idx].Path == "github.com/bbb" {
			found = m.selected[idx]
			_ = i
		}
	}
	if !found {
		t.Error("selection must be keyed by dependency, not row position")
	}
}

// --- Search combined with security status ---

func securityItemsFor(deps []module.Dependency, vulnPath string) []security.DependencyStatus {
	items := make([]security.DependencyStatus, len(deps))
	for i, d := range deps {
		st := security.Status{Checked: true, Severity: security.SeverityNone}
		fix := security.FixUnknown
		if d.Path == vulnPath {
			st.Vulnerabilities = []security.Vulnerability{{
				ID: "GO-2026-9999", Severity: security.SeverityHigh, FixedIn: "v1.2.0",
			}}
			st.Severity = security.SeverityHigh
			fix = security.FixResolved
		}
		items[i] = security.DependencyStatus{Dependency: d, Status: st, Fix: fix}
	}
	return items
}

func TestSearchWithSecurityIndicators(t *testing.T) {
	deps := []module.Dependency{
		{Path: "golang.org/x/net", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "golang.org/x/sync", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/other", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	m := NewModel(deps, securityItemsFor(deps, "golang.org/x/net"), SecurityOn, nil)
	m.handleListKey(key("/"))
	for _, c := range "golang.org/x" {
		m.handleSearchKey(key(string(c)))
	}

	if len(m.visible) != 2 {
		t.Fatalf("search should keep both golang.org deps: %s", joinPaths(m))
	}
	view := m.listView()
	if !strings.Contains(view, "HIGH") {
		t.Error("security badge must remain visible on filtered rows")
	}
	// The vulnerable dep must still rank first (security ordering intact).
	if m.deps[m.visible[0]].Path != "golang.org/x/net" {
		t.Errorf("vulnerable dep should rank first under search: %s", joinPaths(m))
	}
}

func TestSearchWithSecurityOnlyMode(t *testing.T) {
	deps := []module.Dependency{
		{Path: "golang.org/x/net", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "golang.org/x/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/vuln", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	// Both golang.org deps are vulnerable; github.com/vuln also vulnerable.
	m := NewModel(deps, securityItemsFor(deps, "golang.org/x/net"), SecurityOnly, nil)
	// Make golang.org/x/clean clean too by rebuilding its status.
	m.security[1].Status.Vulnerabilities = nil
	m.security[1].Status.Severity = security.SeverityNone
	m.rebuildVisible()

	m.handleListKey(key("/"))
	for _, c := range "golang.org/x" {
		m.handleSearchKey(key(string(c)))
	}

	// Security-only keeps only the vulnerable golang.org dep; the clean
	// golang.org/x/clean must not appear despite matching the search.
	if len(m.visible) != 1 || m.deps[m.visible[0]].Path != "golang.org/x/net" {
		t.Fatalf("search must compose with security-only filter: %s", joinPaths(m))
	}
}

// --- Search with indirect dependencies ---

func TestSearchWithIndirectDependencies(t *testing.T) {
	deps := []module.Dependency{
		{Path: "golang.org/x/net", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "golang.org/x/sync", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0", Indirect: true},
		{Path: "github.com/gin", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0", Indirect: true},
	}
	// Discovery already applied the --indirect filter before the TUI; the
	// model receives the combined list and search filters it.
	m := NewModel(deps, nil, SecurityOff, nil)
	m.handleListKey(key("/"))
	for _, c := range "golang.org/x" {
		m.handleSearchKey(key(string(c)))
	}

	if len(m.visible) != 2 {
		t.Fatalf("search should match direct and indirect: %s", joinPaths(m))
	}
	view := m.listView()
	if !strings.Contains(view, "indirect") {
		t.Error("direct/indirect labels must remain visible on filtered rows")
	}
}

// --- View polish ---

func TestFilterKeptAfterEnterShowsInHeader(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("a"))
	m.handleSearchKey(key("enter"))

	view := m.listView()
	if !strings.Contains(view, "Filter:") || !strings.Contains(view, "a") {
		t.Errorf("kept filter should be visible: %q", view)
	}
	if !strings.Contains(view, "1 match") {
		t.Errorf("kept filter should show match count: %q", view)
	}

	// Esc clears the kept filter without quitting (model still active).
	m.handleListKey(key("esc"))
	if m.query != "" {
		t.Errorf("esc should clear kept filter, query = %q", m.query)
	}
	if len(m.visible) != 2 {
		t.Errorf("full list should be restored: %s", joinPaths(m))
	}
}

func TestQuitWorksAfterSearchModeExited(t *testing.T) {
	m := newSearchModel("github.com/a", "github.com/b")
	m.handleListKey(key("/"))
	m.handleSearchKey(key("esc"))

	// Normal shortcuts active again; q must quit now. We assert the
	// quit command is returned.
	_, cmd := m.handleListKey(key("q"))
	if cmd == nil {
		t.Fatal("q should quit once search mode is exited")
	}
}

func TestHelpShowsSearchBinding(t *testing.T) {
	m := newSearchModel("github.com/a")
	view := m.listView()
	if !strings.Contains(view, "/ Search") {
		t.Error("footer must advertise / Search for discoverability")
	}
}

func TestSearchPerformance(t *testing.T) {
	// Search must be in-memory only: 500 deps filtered repeatedly in
	// well under a second, with no I/O.
	paths := make([]module.Dependency, 500)
	for i := range paths {
		paths[i] = module.Dependency{Path: "github.com/org/repo-" + string(rune('a'+i%26)) + "/" + time.Duration(i).String()}
	}
	m := NewModel(paths, nil, SecurityOff, nil)
	start := time.Now()
	m.handleListKey(key("/"))
	for _, c := range "repo" {
		m.handleSearchKey(key(string(c)))
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("search over 500 deps took %s, want instant", elapsed)
	}
	if len(m.visible) == 0 {
		t.Error("expected matches")
	}
}
