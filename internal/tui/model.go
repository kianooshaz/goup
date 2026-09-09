package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/updater"
)

// screen represents which screen is currently shown.
type screen int

const (
	screenLoading screen = iota
	screenList
	screenConfirm
	screenUpgrading
	screenDone
	screenError
)

// Model is the main Bubble Tea model for the goup TUI.
type Model struct {
	// Dependencies data.
	deps []module.Dependency
	// Selected tracks which dependencies are selected (by index).
	selected map[int]bool

	// UI state.
	screen    screen
	cursor    int
	topIndex  int // first visible item in the viewport
	width     int
	height    int

	// Loading/error state.
	loadingErr error

	// Confirm screen.
	confirmDeps []int // indices of selected deps for confirmation

	// Upgrade state.
	upgradeResults []updater.Result
	upgradeTotal   int
	upgradeErr     error

	// Spinner for loading state.
	spinner spinner.Model

	// Viewport for scrolling.
	viewport viewport.Model

	// Context for cancellation.
	cancel context.CancelFunc

	// Updater reference.
	updater         *updater.Updater
	upgradeProgress chan updater.ProgressUpdate

	// Message to show on the done screen.
	doneMessage string
}

// NewModel creates a new TUI model with the given dependencies and updater.
func NewModel(deps []module.Dependency, u *updater.Updater) *Model {
	s := spinner.New()
	s.Spinner = spinner.Line
	s.Style = infoStyle

	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().Padding(0, 1)

	return &Model{
		deps:      deps,
		selected:  make(map[int]bool),
		screen:    screenList,
		cursor:    0,
		topIndex:  0,
		spinner:   s,
		viewport:  vp,
		updater:   u,
	}
}

// Init initializes the model.
func (m *Model) Init() tea.Cmd {
	if m.screen == screenLoading {
		return m.spinner.Tick
	}
	return nil
}

// Msg types for tea commands.

type upgradeProgressMsg struct {
	progress updater.ProgressUpdate
}

type upgradeStartedMsg struct{}

// startUpgradeMsg triggers the upgrade process.
type startUpgradeMsg struct {
	deps []module.Dependency
}

// screenResizeMsg handles terminal resize events.
type screenResizeMsg struct {
	width  int
	height int
}

// Update handles all message types and state transitions.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 2
		m.viewport.Height = msg.Height - 8
		return m, nil

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)

	case spinner.TickMsg:
		if m.screen == screenLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case startUpgradeMsg:
		return m.startUpgrade(msg.deps)

	case upgradeProgressMsg:
		return m.handleUpgradeProgress(msg.progress)

	case upgradeStartedMsg:
		return m, nil
	}

	return m, tea.Batch(cmds...)
}

// handleKeyMsg processes keyboard input based on the current screen.
func (m *Model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenList:
		return m.handleListKey(msg)
	case screenConfirm:
		return m.handleConfirmKey(msg)
	case screenDone, screenError:
		return m.handleDoneKey(msg)
	case screenUpgrading:
		// During upgrade, only allow quitting on completion.
		return m, nil
	}
	return m, nil
}

// handleListKey processes keyboard input on the list screen.
func (m *Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.ensureCursorVisible()
		}

	case "down", "j":
		if m.cursor < len(m.deps)-1 {
			m.cursor++
			m.ensureCursorVisible()
		}

	case " ":
		m.toggleSelection(m.cursor)

	case "a":
		m.selectAll()

	case "n":
		m.selectNone()

	case "enter":
		return m.handleEnter()

	case "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// handleConfirmKey processes input on the confirmation screen.
func (m *Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		// Go back to list.
		m.screen = screenList
		return m, nil

	case "enter":
		// Proceed with upgrade.
		var deps []module.Dependency
		for _, idx := range m.confirmDeps {
			deps = append(deps, m.deps[idx])
		}
		m.screen = screenUpgrading
		m.upgradeTotal = len(deps)
		m.upgradeResults = nil
		return m, func() tea.Msg {
			return startUpgradeMsg{deps: deps}
		}

	case "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// handleDoneKey processes input on the done/error screen.
func (m *Model) handleDoneKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "enter", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// handleEnter transitions to the confirmation or upgrade screen.
func (m *Model) handleEnter() (tea.Model, tea.Cmd) {
	selected := m.selectedIndices()
	if len(selected) == 0 {
		return m, nil // No selection; do nothing.
	}

	m.confirmDeps = selected
	m.screen = screenConfirm
	return m, nil
}

// toggleSelection toggles the selection state of the dependency at index i.
func (m *Model) toggleSelection(i int) {
	if m.selected[i] {
		delete(m.selected, i)
	} else {
		m.selected[i] = true
	}
}

// selectAll selects all currently displayed dependencies.
func (m *Model) selectAll() {
	for i := range m.deps {
		m.selected[i] = true
	}
}

// selectNone deselects all dependencies.
func (m *Model) selectNone() {
	m.selected = make(map[int]bool)
}

// selectedIndices returns the indices of all selected dependencies in order.
func (m *Model) selectedIndices() []int {
	var indices []int
	for i := range m.deps {
		if m.selected[i] {
			indices = append(indices, i)
		}
	}
	return indices
}

// ensureCursorVisible adjusts topIndex so the cursor is visible.
func (m *Model) ensureCursorVisible() {
	visibleHeight := m.viewport.Height - 2 // account for borders
	if visibleHeight <= 0 {
		return
	}
	if m.cursor < m.topIndex {
		m.topIndex = m.cursor
	}
	if m.cursor >= m.topIndex+visibleHeight {
		m.topIndex = m.cursor - visibleHeight + 1
	}
}

// startUpgrade begins the upgrade process by launching a goroutine.
func (m *Model) startUpgrade(deps []module.Dependency) (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	progress := make(chan updater.ProgressUpdate, 10)
	m.upgradeProgress = progress

	go m.updater.Upgrade(ctx, deps, progress)

	return m, m.waitForUpgrade(progress)
}

// waitForUpgrade returns a command that reads from the progress channel.
func (m *Model) waitForUpgrade(progress <-chan updater.ProgressUpdate) tea.Cmd {
	return func() tea.Msg {
		p, ok := <-progress
		if !ok {
			// Channel closed, upgrade done.
			return upgradeProgressMsg{
				progress: updater.ProgressUpdate{Done: true},
			}
		}
		return upgradeProgressMsg{progress: p}
	}
}

// handleUpgradeProgress processes a progress update from the upgrade goroutine.
func (m *Model) handleUpgradeProgress(p updater.ProgressUpdate) (tea.Model, tea.Cmd) {
	if p.Done {
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		if p.Err != nil {
			m.upgradeErr = p.Err
		}
		m.screen = screenDone
		return m, nil
	}

	m.upgradeResults = append(m.upgradeResults, p.Result)
	m.upgradeTotal = p.Total

	// Read the next message.
	return m, m.waitForUpgrade(m.upgradeProgress)
}

// View renders the current screen.
func (m *Model) View() string {
	switch m.screen {
	case screenLoading:
		return m.loadingView()
	case screenList:
		return m.listView()
	case screenConfirm:
		return m.confirmView()
	case screenUpgrading:
		return m.upgradingView()
	case screenDone:
		return m.doneView()
	case screenError:
		return m.errorView()
	}
	return ""
}

// loadingView shows a spinner while checking dependencies.
func (m *Model) loadingView() string {
	return fmt.Sprintf("\n  %s Checking dependencies...\n", m.spinner.View())
}

// listView renders the main dependency list.
func (m *Model) listView() string {
	var b strings.Builder

	// Title.
	b.WriteString(titleStyle.Render("\n  goup — Go dependency updater"))
	b.WriteString("\n\n")

	// Subtitle.
	updatesCount := len(m.deps)
	b.WriteString(subtitleStyle.Render(fmt.Sprintf("  %d updates available", updatesCount)))
	b.WriteString("\n\n")

	// Column headers.
	columns := fmt.Sprintf("  %-45s %-12s %-12s %s",
		"Dependency", "Current", "Latest", "Type")
	b.WriteString(dimmedStyle.Render(columns))
	b.WriteString("\n")
	b.WriteString(dimmedStyle.Render(strings.Repeat("─", max(m.width-4, 50))))
	b.WriteString("\n")

	// Dependency list with viewport.
	visibleHeight := m.viewport.Height - 2
	if visibleHeight <= 0 {
		visibleHeight = 10
	}
	end := m.topIndex + visibleHeight
	if end > len(m.deps) {
		end = len(m.deps)
	}

	for i := m.topIndex; i < end; i++ {
		dep := m.deps[i]
		selected := m.selected[i]
		isCursor := i == m.cursor

		b.WriteString(m.renderItem(dep, selected, isCursor))
		b.WriteString("\n")
	}

	// Footer.
	b.WriteString("\n")

	// Selection count.
	selectedCount := len(m.selectedIndices())
	if selectedCount > 0 {
		b.WriteString(fmt.Sprintf("  %s %d selected\n", infoStyle.Render("●"), selectedCount))
	} else {
		b.WriteString(fmt.Sprintf("  %s no dependencies selected\n", dimmedStyle.Render("○")))
	}

	// Help bar.
	b.WriteString("\n")
	b.WriteString(m.renderHelp())

	if m.topIndex > 0 || end < len(m.deps) {
		b.WriteString(fmt.Sprintf("\n  %s", dimmedStyle.Render(fmt.Sprintf(
			"Showing %d-%d of %d", m.topIndex+1, end, len(m.deps)))))
	}

	return appStyle.Render(b.String())
}

// renderItem renders a single dependency line.
func (m *Model) renderItem(dep module.Dependency, selected bool, isCursor bool) string {
	// Checkbox.
	checkbox := checkboxEmpty
	if selected {
		checkbox = checkboxSelected
	}

	// Dependency type label.
	depType := "direct"
	depTypeStyle := dimmedStyle
	if dep.Indirect {
		depType = "indirect"
		depTypeStyle = mutedStyle
	}

	// Version info.
	currentVer := dep.CurrentVersion
	latestVer := dep.LatestVersion

	// Build the line.
	line := fmt.Sprintf("  %s %-42s %-12s %s %-12s %s",
		checkbox,
		dep.Path,
		currentVer,
		versionArrow,
		latestVer,
		depTypeStyle.Render(depType),
	)

	style := itemStyle
	if selected {
		style = selectedItemStyle
	}
	if isCursor {
		line = cursorStyle.Render(line)
		return style.Render(line)
	}

	return style.Render(line)
}

// renderHelp shows the keyboard shortcuts.
func (m *Model) renderHelp() string {
	k := keyMap{}
	bindings := k.help()
	var parts []string
	for _, b := range bindings {
		parts = append(parts, fmt.Sprintf("%s %s",
			infoStyle.Render(b.key),
			dimmedStyle.Render(b.desc)))
	}
	return strings.Join(parts, "  ")
}

// confirmView shows the confirmation screen.
func (m *Model) confirmView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  Upgrade dependencies"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %s\n\n", infoStyle.Render(fmt.Sprintf(
		"%d dependencies selected", len(m.confirmDeps)))))

	for _, idx := range m.confirmDeps {
		dep := m.deps[idx]
		b.WriteString(fmt.Sprintf("  %s\n", dep.Path))
		b.WriteString(fmt.Sprintf("    %s %s %s %s\n",
			dimmedStyle.Render(dep.CurrentVersion),
			versionArrow,
			successStyle.Render(dep.LatestVersion),
			dimmedStyle.Render("("+dep.UpdateType.String()+")"),
		))
	}

	b.WriteString("\n")
	b.WriteString(dimmedStyle.Render("  The resulting go.mod may include additional changes due to Go's module graph resolution."))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		successStyle.Render("Enter"),
		dimmedStyle.Render("Upgrade"),
	))
	b.WriteString(fmt.Sprintf("  %s  %s\n",
		infoStyle.Render("Esc"),
		dimmedStyle.Render("Cancel"),
	))

	return appStyle.Render(b.String())
}

// upgradingView shows progress during the upgrade.
func (m *Model) upgradingView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  Upgrading dependencies..."))
	b.WriteString("\n\n")

	// Show results so far.
	for _, r := range m.upgradeResults {
		marker := markerSuccess
		style := successStyle
		if !r.Success {
			marker = markerError
			style = errorStyle
		}
		b.WriteString(fmt.Sprintf("  %s %s\n",
			style.Render(marker),
			r.Path,
		))
		if !r.Success && r.Error != "" {
			b.WriteString(fmt.Sprintf("    %s\n", errorStyle.Render(r.Error)))
		}
	}

	// Show pending count.
	pending := m.upgradeTotal - len(m.upgradeResults)
	for i := 0; i < pending && i < 5; i++ {
		b.WriteString(fmt.Sprintf("  %s %s\n",
			dimmedStyle.Render(markerPending),
			dimmedStyle.Render("pending..."),
		))
	}
	if pending > 5 {
		b.WriteString(fmt.Sprintf("  %s\n",
			dimmedStyle.Render(fmt.Sprintf("  ... and %d more", pending-5))))
	}

	b.WriteString(fmt.Sprintf("\n  %s\n",
		infoStyle.Render(fmt.Sprintf("%d / %d completed", len(m.upgradeResults), m.upgradeTotal))))

	// Running go mod tidy?
	if len(m.upgradeResults) == m.upgradeTotal && m.upgradeTotal > 0 {
		b.WriteString(fmt.Sprintf("\n  %s Running go mod tidy...\n", dimmedStyle.Render(markerPending)))
	}

	return appStyle.Render(b.String())
}

// doneView shows the final upgrade results.
func (m *Model) doneView() string {
	var b strings.Builder

	if m.upgradeErr != nil {
		b.WriteString(titleStyle.Render("\n  Upgrade finished with errors"))
		b.WriteString("\n\n")
	} else {
		b.WriteString(titleStyle.Render("\n  ✓ Upgrade completed"))
		b.WriteString("\n\n")
	}

	// Show all results.
	var succeeded, failed int
	for _, r := range m.upgradeResults {
		if r.Success {
			succeeded++
			b.WriteString(fmt.Sprintf("  %s %s\n",
				successStyle.Render(markerSuccess),
				r.Path,
			))
			b.WriteString(fmt.Sprintf("    %s %s %s\n",
				dimmedStyle.Render(r.OldVersion),
				versionArrow,
				successStyle.Render(r.NewVersion),
			))
		} else {
			failed++
			b.WriteString(fmt.Sprintf("  %s %s\n",
				errorStyle.Render(markerError),
				r.Path,
			))
			if r.Error != "" {
				b.WriteString(fmt.Sprintf("    %s\n", errorStyle.Render(r.Error)))
			}
		}
	}

	skipped := m.upgradeTotal - succeeded - failed
	if skipped > 0 {
		b.WriteString(fmt.Sprintf("  %s %d additional skipped\n",
			dimmedStyle.Render(markerSkipped), skipped))
	}

	// Summary.
	b.WriteString("\n")
	b.WriteString(dimmedStyle.Render(fmt.Sprintf(
		"%d succeeded", succeeded)))
	if failed > 0 {
		b.WriteString(fmt.Sprintf("  %s",
			errorStyle.Render(fmt.Sprintf("%d failed", failed))))
	}
	if skipped > 0 {
		b.WriteString(fmt.Sprintf("  %s",
			dimmedStyle.Render(fmt.Sprintf("%d skipped", skipped))))
	}

	if m.upgradeErr != nil {
		b.WriteString(fmt.Sprintf("\n\n  %s\n", errorStyle.Render(m.upgradeErr.Error())))
	}

	b.WriteString(fmt.Sprintf("\n\n  %s  %s\n",
		infoStyle.Render("q/Esc/Enter"),
		dimmedStyle.Render("Quit"),
	))

	return appStyle.Render(b.String())
}

// errorView shows an unexpected error.
func (m *Model) errorView() string {
	var b strings.Builder
	b.WriteString(errorStyle.Render("\n  ✗ Error"))
	b.WriteString("\n\n")
	if m.loadingErr != nil {
		b.WriteString(fmt.Sprintf("  %s\n", m.loadingErr.Error()))
	}

	b.WriteString(fmt.Sprintf("\n  %s  %s\n",
		infoStyle.Render("q/Esc"),
		dimmedStyle.Render("Quit"),
	))
	return appStyle.Render(b.String())
}

// SetLoadingErr sets an error and switches to the error screen.
func (m *Model) SetLoadingErr(err error) {
	m.loadingErr = err
	m.screen = screenError
}

// HasSelection returns true if any dependencies are selected.
func (m *Model) HasSelection() bool {
	return len(m.selectedIndices()) > 0
}
