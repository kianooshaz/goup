package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kianooshaz/goup/internal/module"
	"github.com/kianooshaz/goup/internal/pipeline"
	"github.com/kianooshaz/goup/internal/security"
	"github.com/kianooshaz/goup/internal/updater"
)

// screen represents which screen is currently shown.
type screen int

const (
	screenLoading screen = iota
	screenList
	screenSkipped
	screenDetail
	screenConfirm
	screenUpgrading
	screenDone
	screenError
)

// SecurityMode determines how security data appears in the list.
type SecurityMode int

const (
	// SecurityOn shows badges, summary, and security-first sorting.
	SecurityOn SecurityMode = iota
	// SecurityOnly filters the list to vulnerable dependencies.
	SecurityOnly
	// SecurityOff hides all security columns and sorting.
	SecurityOff
)

// Model is the main Bubble Tea model for the goup TUI.
type Model struct {
	// Dependencies data.
	deps []module.Dependency
	// Selected tracks which dependencies are selected (by index into deps).
	selected map[int]bool

	// Security data. security aligns by index with deps; visible holds the
	// indices of deps shown on the list screen (all of them, or only
	// vulnerable ones in security-only mode).
	security []security.DependencyStatus
	visible  []int
	secMode  SecurityMode

	// Modules that could not be processed during discovery; shown on the
	// skipped detail screen.
	skipped []module.SkippedDependency

	// Search state: query filters visible by module path, searching is
	// true while the search input has focus. Selections are keyed by
	// dependency index and are unaffected by filtering.
	query     string
	searching bool

	// Detail view state: index into security/deps shown on screenDetail.
	detailIndex int

	// UI state.
	screen   screen
	cursor   int
	topIndex int // first visible item in the viewport
	width    int
	height   int

	// Loading/error state.
	loadingErr   error
	loadingStage pipeline.Stage
	loadingMod   string // module currently being processed
	loadingDone  int
	loadingTotal int
	haveResult   bool // discovery finished at least once

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

	// pipelineMsgs carries pipeline events (progress, then exactly one
	// result or error) from the background goroutine to the UI. Each
	// message is followed by a fresh waitForPipeline command so the
	// channel keeps being drained until it closes.
	pipelineMsgs <-chan tea.Msg

	// initCmd, when set, is returned by Init once — used to launch the
	// background discovery pipeline as the program's initial command.
	initCmd tea.Cmd
}

// NewModel creates a TUI model in the loading state: the UI starts
// immediately and the pipeline fills in deps/security/skipped via
// ApplyResult as discovery progresses in the background.
func NewModel(u *updater.Updater, mode SecurityMode) *Model {
	s := spinner.New()
	s.Spinner = spinner.Line
	s.Style = infoStyle

	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().Padding(0, 1)

	return &Model{
		selected: make(map[int]bool),
		secMode:  mode,
		screen:   screenLoading,
		spinner:  s,
		viewport: vp,
		updater:  u,
	}
}

// ApplyResult incorporates a completed pipeline result. The first result
// transitions from the loading screen to the list; later results (none in
// the current single-shot pipeline) would refresh data in place.
func (m *Model) ApplyResult(res pipeline.Result) {
	m.deps = res.Dependencies
	m.skipped = res.Skipped
	if res.SecurityDisabled {
		m.secMode = SecurityOff
	} else if res.Security != nil {
		m.security = res.Security
	}
	m.haveResult = true
	m.rebuildVisible()
	m.screen = screenList
}

// SetInitCmd registers a command for Init to return on the first call.
// Used by the CLI to launch the background discovery pipeline.
func (m *Model) SetInitCmd(cmd tea.Cmd) {
	m.initCmd = cmd
}

// SetLoadingError records a fatal pipeline failure and switches to the
// error screen.
func (m *Model) SetLoadingError(err error) {
	m.loadingErr = err
	m.screen = screenError
}

// rebuildVisible recomputes which dependency indices the list shows,
// applying the filter pipeline in order:
//
//	all deps → security-only filter → search filter →
//	security-urgency sort → search prefix rank
//
// Every stage is stable, so the discovery order survives where no stage
// has an opinion. The cursor is clamped to the new range.
func (m *Model) rebuildVisible() {
	m.visible = m.visible[:0]
	securityAvailable := m.hasSecurityData()
	if m.secMode == SecurityOnly && securityAvailable {
		for i := range m.deps {
			if !m.security[i].Status.CheckedOK() || len(m.security[i].Status.Vulnerabilities) == 0 {
				continue
			}
			m.visible = append(m.visible, i)
		}
	} else {
		m.visible = m.applySearchFilter(m.visible, m.query)
	}

	if m.secMode == SecurityOnly && securityAvailable && m.query != "" {
		filtered := m.applySearchFilter(nil, m.query)
		// Keep only the search matches within the security-only list,
		// preserving that list's severity ordering.
		keep := make(map[int]bool, len(filtered))
		for _, i := range filtered {
			keep[i] = true
		}
		out := m.visible[:0]
		for _, i := range m.visible {
			if keep[i] {
				out = append(out, i)
			}
		}
		m.visible = out
	}

	// Security-urgency sorting needs aligned security data; it is absent
	// when the pipeline skipped the check, so sort only when it exists.
	if m.hasSecurityData() {
		sort.SliceStable(m.visible, func(a, b int) bool {
			return secUrgency(m.security[m.visible[a]]) > secUrgency(m.security[m.visible[b]])
		})
	}
	m.rankBySearch(m.query)

	if m.cursor >= len(m.visible) {
		m.cursor = max(len(m.visible)-1, 0)
	}
	if m.topIndex > m.cursor {
		m.topIndex = m.cursor
	}
	// Guard against an offset past the end of a now-shorter list: the render
	// loop starts at topIndex, so an out-of-range offset would draw no rows
	// at all despite there being matches.
	if m.topIndex >= len(m.visible) {
		m.topIndex = max(len(m.visible)-1, 0)
	}
}

// secUrgency ranks a dependency for list ordering: vulnerable deps by
// severity, failed checks above clean deps, clean deps last.
func secUrgency(item security.DependencyStatus) int {
	switch {
	case item.Status.CheckedOK() && len(item.Status.Vulnerabilities) > 0:
		return 10 + item.Status.Severity.Rank()
	case !item.Status.CheckedOK():
		return 5
	default:
		return 0
	}
}

// hasSecurityData reports whether per-dependency security statuses are
// present and aligned by index with deps. It is false when the check was
// disabled (--no-security), when the pipeline reported it disabled, or
// before the result has arrived. Every place that indexes m.security must
// consult it first.
func (m *Model) hasSecurityData() bool {
	return m.secMode != SecurityOff && len(m.deps) > 0 && len(m.security) == len(m.deps)
}

// securityFor returns the security status for a deps index, or a
// disabled/unchecked status when security data is absent.
func (m *Model) securityFor(i int) security.DependencyStatus {
	if i < 0 || i >= len(m.security) {
		return security.DependencyStatus{}
	}
	return m.security[i]
}

// Init initializes the model.
func (m *Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	if m.initCmd != nil {
		cmds = append(cmds, m.initCmd)
		m.initCmd = nil // fire once
	}
	if m.screen == screenLoading {
		cmds = append(cmds, m.spinner.Tick)
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}

// Msg types for tea commands.

type upgradeProgressMsg struct {
	progress updater.ProgressUpdate
}

// startUpgradeMsg triggers the upgrade process.
type startUpgradeMsg struct {
	deps []module.Dependency
}

// pipelineProgressMsg reports a loading-phase progress snapshot from the
// background pipeline.
type pipelineProgressMsg struct {
	progress pipeline.Progress
}

// pipelineResultMsg carries the completed discovery/security result.
type pipelineResultMsg struct {
	result pipeline.Result
}

// pipelineErrMsg carries a fatal pipeline failure (whole-run error, not a
// per-dependency skip).
type pipelineErrMsg struct {
	err error
}

// StartPipeline launches the discovery pipeline in the background and
// returns the command that starts delivering its events to the UI. The TUI
// renders the loading screen immediately and stays responsive.
//
// A dedicated goroutine multiplexes the pipeline's progress and outcome
// channels onto one message channel, which the UI drains with
// waitForPipeline — re-armed after every progress event so the stream is
// read to completion. The pipeline itself sends exactly one outcome, so the
// multiplexer stops after forwarding it.
func (m *Model) StartPipeline(p *pipeline.Pipeline, includeIndirect bool) tea.Cmd {
	progress := make(chan pipeline.Progress, 16)
	results := make(chan pipeline.Result, 1)
	errs := make(chan error, 1)

	ctx, cancel := context.WithTimeout(context.Background(), pipeline.Deadline)
	m.cancel = cancel

	go func() {
		defer close(results)
		defer close(errs)
		p.Run(ctx, includeIndirect, m.secMode != SecurityOff, progress, results, errs)
	}()

	msgs := make(chan tea.Msg, 16)
	m.pipelineMsgs = msgs

	go func() {
		defer close(msgs)

		// progress is closed by Run only after it has delivered its single
		// outcome, and results/errs are closed just after that. Because
		// several channels can be closed at once, a closed channel is
		// disabled (set to nil) rather than treated as an outcome — a plain
		// select over them could otherwise pick a closed errs/results and
		// exit without ever forwarding the buffered result, stranding the
		// UI on the loading screen.
		for progress != nil || results != nil || errs != nil {
			select {
			case pr, ok := <-progress:
				if !ok {
					progress = nil
					continue
				}
				select {
				case msgs <- pipelineProgressMsg{progress: pr}:
				case <-ctx.Done():
					return
				}

			case res, ok := <-results:
				if !ok {
					results = nil
					continue
				}
				select {
				case msgs <- pipelineResultMsg{result: res}:
				case <-ctx.Done():
				}
				return

			case err, ok := <-errs:
				if !ok {
					errs = nil
					continue
				}
				select {
				case msgs <- pipelineErrMsg{err: err}:
				case <-ctx.Done():
				}
				return

			case <-ctx.Done():
				select {
				case msgs <- pipelineErrMsg{err: ctx.Err()}:
				default:
				}
				return
			}
		}
	}()

	return m.waitForPipeline()
}

// waitForPipeline returns a command that delivers the next pipeline event.
// It is re-armed after each progress message (see Update) and a nil message
// is returned once the stream is closed.
func (m *Model) waitForPipeline() tea.Cmd {
	msgs := m.pipelineMsgs
	if msgs == nil {
		return nil
	}
	return func() tea.Msg {
		msg, ok := <-msgs
		if !ok {
			return nil
		}
		return msg
	}
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
		// Keep the spinner animating on the loading screen.
		if m.screen == screenLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case pipelineProgressMsg:
		m.loadingStage = msg.progress.Stage
		m.loadingMod = msg.progress.Module
		m.loadingDone = msg.progress.Done
		m.loadingTotal = msg.progress.Total
		// Re-arm the reader: the pipeline sends many progress events before
		// its single result, so stopping here would strand the run on the
		// loading screen.
		return m, m.waitForPipeline()

	case pipelineResultMsg:
		m.ApplyResult(msg.result)
		return m, nil

	case pipelineErrMsg:
		m.SetLoadingError(msg.err)
		return m, nil

	case startUpgradeMsg:
		return m.startUpgrade(msg.deps)

	case upgradeProgressMsg:
		return m.handleUpgradeProgress(msg.progress)
	}

	return m, tea.Batch(cmds...)
}

// handleKeyMsg processes keyboard input based on the current screen.
func (m *Model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenLoading:
		// Allow quitting while loading; everything else is ignored so the
		// phase completes undisturbed.
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		return m, nil
	case screenList:
		return m.handleListKey(msg)
	case screenSkipped:
		return m.handleSkippedKey(msg)
	case screenDetail:
		return m.handleDetailKey(msg)
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

// handleSkippedKey processes input on the skipped-dependencies screen.
func (m *Model) handleSkippedKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "s", "enter", "ctrl+c":
		m.screen = screenList
		return m, nil
	}
	return m, nil
}

// handleDetailKey processes input on the security detail screen.
func (m *Model) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "d", "enter", "ctrl+c":
		m.screen = screenList
		return m, nil
	}
	return m, nil
}

// handleListKey processes keyboard input on the list screen. While the
// search input has focus, all keys are handled by handleSearchKey instead.
func (m *Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searching {
		return m.handleSearchKey(msg)
	}

	switch msg.String() {
	case "/":
		m.enterSearch()
		return m, nil

	case "q":
		return m, tea.Quit

	case "esc":
		// Esc with an active (kept) filter clears it; with no filter it
		// quits as before.
		if m.query != "" {
			m.setQuery("")
			return m, nil
		}
		return m, tea.Quit

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.ensureCursorVisible()
		}

	case "down", "j":
		if m.cursor < len(m.visible)-1 {
			m.cursor++
			m.ensureCursorVisible()
		}

	case " ":
		m.toggleSelection(m.cursor)

	case "a":
		m.selectAll()

	case "n":
		m.selectNone()

	case "d":
		// Security details only exist when the check ran and its statuses
		// are aligned with the dependency list.
		if len(m.visible) > 0 && m.hasSecurityData() {
			m.detailIndex = m.visible[m.cursor]
			m.screen = screenDetail
		}

	case "s":
		if len(m.skipped) > 0 {
			m.screen = screenSkipped
		}

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

// toggleSelection toggles the selection state of the visible row at index i.
func (m *Model) toggleSelection(i int) {
	if i < 0 || i >= len(m.visible) {
		return
	}
	depIdx := m.visible[i]
	if m.selected[depIdx] {
		delete(m.selected, depIdx)
	} else {
		m.selected[depIdx] = true
	}
}

// selectAll selects all currently displayed dependencies.
func (m *Model) selectAll() {
	for _, depIdx := range m.visible {
		m.selected[depIdx] = true
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
	case screenSkipped:
		return m.skippedView()
	case screenDetail:
		return m.detailView()
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

// loadingView shows the spinner, the current operation, and progress so
// the user always knows whether goup is working, waiting, or finished.
func (m *Model) loadingView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  goup — Go dependency updater"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %s %s\n", m.spinner.View(), infoStyle.Render(m.loadingStage.String())))

	// Detail line: the module being checked, plus numeric progress when
	// the total is known.
	if m.loadingMod != "" {
		b.WriteString(fmt.Sprintf("  %s Checking %s\n",
			dimmedStyle.Render("·"), m.loadingMod))
	}
	if m.loadingTotal > 0 {
		b.WriteString(fmt.Sprintf("  %s %d of %d\n",
			dimmedStyle.Render("·"), m.loadingDone, m.loadingTotal))
	}

	b.WriteString(fmt.Sprintf("\n  %s\n", dimmedStyle.Render("q Cancel")))
	return appStyle.Render(b.String())
}

// skippedView lists modules that could not be processed during discovery.
// It never blocks the main workflow: the list screen stays fully usable.
func (m *Model) skippedView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("\n  Skipped dependencies"))
	b.WriteString("\n\n")

	if len(m.skipped) == 0 {
		b.WriteString(successStyle.Render("  ✓ Nothing was skipped") + "\n")
	}

	for _, s := range m.skipped {
		b.WriteString(fmt.Sprintf("  %s %s\n", warningStyle.Render("⚠"), s.Path))
		reason := "unknown reason"
		if s.Reason != nil {
			reason = s.Reason.Error()
		}
		b.WriteString(fmt.Sprintf("    %s %s\n", dimmedStyle.Render("reason:"), dimmedStyle.Render(reason)))
	}

	b.WriteString(fmt.Sprintf("\n  %s  %s\n",
		infoStyle.Render("Esc/s"),
		dimmedStyle.Render("Back"),
	))
	return appStyle.Render(b.String())
}

// listView renders the main dependency list.
func (m *Model) listView() string {
	var b strings.Builder

	// Title.
	b.WriteString(titleStyle.Render("\n  goup — Go dependency updater"))
	b.WriteString("\n\n")

	// Search input line while search mode is active.
	if m.searching {
		b.WriteString(fmt.Sprintf("  %s %s█\n",
			infoStyle.Render("Search:"),
			m.query))
		b.WriteString("\n")
	} else if m.query != "" {
		// A kept filter from a previous search (Enter exits search mode
		// without clearing).
		b.WriteString(fmt.Sprintf("  %s %s  %s\n",
			dimmedStyle.Render("Filter:"),
			m.query,
			dimmedStyle.Render(fmt.Sprintf("(%d match%s)", len(m.visible), plural(len(m.visible))))))
	}

	// Subtitle and security summary.
	updatesCount := len(m.visible)
	if !m.searchActive() {
		label := fmt.Sprintf("%d updates available", updatesCount)
		if m.secMode == SecurityOnly {
			label = fmt.Sprintf("%d vulnerable %s", updatesCount, pluralWord(updatesCount, "dependency", "dependencies"))
		}
		b.WriteString(subtitleStyle.Render("  " + label))
		b.WriteString("\n")
	}
	switch {
	case m.secMode == SecurityOff:
		b.WriteString(dimmedStyle.Render("  security check disabled (--no-security)") + "\n")
	case m.hasSecurityData():
		if summary := Summarize(m.security); summary.HasIssues() {
			b.WriteString("  " + summary.Render() + "\n")
		}
	}
	b.WriteString("\n")

	// Empty result state: no matches at all.
	if len(m.visible) == 0 {
		// A skipped count is surfaced in every empty state so absence is
		// never mistaken for a clean result.
		writeSkipped := func() {
			if n := len(m.skipped); n > 0 {
				b.WriteString(fmt.Sprintf("  %s %d dependencies skipped (%s for details)\n",
					warningStyle.Render("⚠"), n, infoStyle.Render("s")))
			}
		}

		switch {
		case m.searchActive():
			// A search or kept filter matched nothing.
			b.WriteString(dimmedStyle.Render("  No dependencies found.") + "\n\n")
			b.WriteString(fmt.Sprintf("  %s %s\n",
				infoStyle.Render("Esc"),
				dimmedStyle.Render("Clear search")))
		case m.secMode == SecurityOnly && m.haveResult:
			// --security with an empty list. A clean result can only be
			// claimed when every check actually completed: dependencies whose
			// check failed are filtered out of this view, so "nothing shown"
			// must not be read as "nothing vulnerable" when the database was
			// unreachable.
			summary := Summarize(m.security)
			switch {
			case summary.FailedChecks > 0:
				b.WriteString(warningStyle.Render(fmt.Sprintf(
					"  ⚠ No confirmed vulnerabilities, but %d %s could not be checked.",
					summary.FailedChecks,
					pluralWord(summary.FailedChecks, "dependency", "dependencies"))) + "\n")
				b.WriteString(dimmedStyle.Render(
					"    Run without --security to see every dependency and the failures.") + "\n")
			default:
				b.WriteString(successStyle.Render("  ✓ No vulnerable dependencies among the available updates.") + "\n")
			}
			writeSkipped()
		case m.haveResult:
			// Nothing filtered, so everything is already current.
			b.WriteString(successStyle.Render("  ✓ All dependencies are up to date.") + "\n")
			writeSkipped()
		default:
			b.WriteString(dimmedStyle.Render("  No dependencies found.") + "\n")
		}
		return appStyle.Render(b.String())
	}

	// Column headers, aligned with renderItem's cells: the dependency
	// column accounts for the two-cell checkbox prefix, and an empty cell
	// stands in for the version arrow.
	columns := fmt.Sprintf("  %s %s %s %s %s",
		padRight("Dependency", depColumnWidth+2),
		padRight("Current", versionColumnWidth),
		" ",
		padRight("Latest", versionColumnWidth),
		padRight("Type", depTypeColumnWidth))
	if m.hasSecurityData() {
		columns += "  Security"
	}
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
	if end > len(m.visible) {
		end = len(m.visible)
	}

	for row := m.topIndex; row < end; row++ {
		depIdx := m.visible[row]
		dep := m.deps[depIdx]
		selected := m.selected[depIdx]
		isCursor := row == m.cursor

		b.WriteString(m.renderItem(depIdx, dep, selected, isCursor))
		b.WriteString("\n")
	}

	// Footer.
	b.WriteString("\n")

	// Match count while searching, subtle and non-intrusive.
	if m.searching {
		b.WriteString(fmt.Sprintf("  %s\n",
			dimmedStyle.Render(fmt.Sprintf("%d of %d dependencies match",
				len(m.visible), len(m.deps)))))
	}

	// Selection count.
	selectedCount := len(m.selectedIndices())
	switch {
	case selectedCount == 0:
		b.WriteString(fmt.Sprintf("  %s no dependencies selected\n", dimmedStyle.Render("○")))
	case m.secMode == SecurityOnly:
		b.WriteString(fmt.Sprintf("  %s %d selected (%s)\n",
			infoStyle.Render("●"), selectedCount,
			dimmedStyle.Render("vulnerable dependencies")))
	default:
		b.WriteString(fmt.Sprintf("  %s %d selected\n", infoStyle.Render("●"), selectedCount))
	}

	// Skipped-dependency count so absence is never mistaken for a clean
	// result. "s" opens the detail list.
	if n := len(m.skipped); n > 0 {
		b.WriteString(fmt.Sprintf("  %s %d dependencies skipped (%s for details)\n",
			warningStyle.Render("⚠"), n, infoStyle.Render("s")))
	}

	// Help bar.
	b.WriteString("\n")
	b.WriteString(m.renderHelp())

	if m.topIndex > 0 || end < len(m.visible) {
		b.WriteString(fmt.Sprintf("\n  %s", dimmedStyle.Render(fmt.Sprintf(
			"Showing %d-%d of %d", m.topIndex+1, end, len(m.visible)))))
	}

	return appStyle.Render(b.String())
}

// renderItem renders a single dependency line.
func (m *Model) renderItem(depIdx int, dep module.Dependency, selected bool, isCursor bool) string {
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

	// Security column. Rendered only when statuses are present, matching the
	// header, so the columns can never disagree about its presence.
	secCol := ""
	if m.hasSecurityData() {
		item := m.securityFor(depIdx)
		secCol = "  " + securityColumn(item)
		if note := fixNote(item); note != "" {
			secCol += "  " + note
		}
	}

	// Build the line. Columns are padded by display width, not byte count,
	// so long or non-ASCII module paths cannot shift the columns after them.
	line := fmt.Sprintf("  %s %s %s %s %s %s%s",
		checkbox,
		padRight(dep.Path, depColumnWidth),
		padRight(dep.CurrentVersion, versionColumnWidth),
		versionArrow,
		padRight(dep.LatestVersion, versionColumnWidth),
		depTypeStyle.Render(padRight(depType, depTypeColumnWidth)),
		secCol,
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

// Column widths for the dependency list, measured in display cells.
const (
	depColumnWidth     = 42
	versionColumnWidth = 12
	depTypeColumnWidth = 8 // widest label is "indirect"
)

// padRight pads s with spaces to width display cells. It measures with
// lipgloss.Width so multi-byte and wide characters do not over-pad; strings
// already at or beyond width are returned unchanged, and one trailing space
// always separates a long value from the next column.
func padRight(s string, width int) string {
	if gap := width - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return s + " "
}

// renderHelp shows the keyboard shortcuts. Bindings adapt to mode:
// security-related keys are hidden when disabled, and search mode swaps
// the footer for its own control hints.
func (m *Model) renderHelp() string {
	if m.searching {
		return strings.Join([]string{
			fmt.Sprintf("%s %s", infoStyle.Render("Type"), dimmedStyle.Render("Search")),
			fmt.Sprintf("%s %s", infoStyle.Render("↑/↓"), dimmedStyle.Render("Navigate")),
			fmt.Sprintf("%s %s", infoStyle.Render("Space"), dimmedStyle.Render("Select")),
			fmt.Sprintf("%s %s", infoStyle.Render("Enter"), dimmedStyle.Render("Apply")),
			fmt.Sprintf("%s %s", infoStyle.Render("Esc"), dimmedStyle.Render("Clear")),
		}, "  ")
	}

	k := keyMap{}
	bindings := k.help()
	// Hide the security-details hint whenever there is no security data to
	// show (--no-security, or a pipeline that reported the check disabled).
	if !m.hasSecurityData() {
		filtered := bindings[:0]
		for _, b := range bindings {
			if b.key != "d" {
				filtered = append(filtered, b)
			}
		}
		bindings = filtered
	}
	var parts []string
	for _, b := range bindings {
		parts = append(parts, fmt.Sprintf("%s %s",
			infoStyle.Render(b.key),
			dimmedStyle.Render(b.desc)))
	}
	return strings.Join(parts, "  ")
}

// plural returns "" for 1 and "s" otherwise, for match counts.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// pluralWord picks the singular or plural word for a count.
func pluralWord(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
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
