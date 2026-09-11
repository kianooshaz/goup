package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// App styles.
	appStyle = lipgloss.NewStyle().
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Padding(0, 0, 0, 0)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	// List item styles.
	itemStyle = lipgloss.NewStyle().
			Padding(0, 2, 0, 0)

	selectedItemStyle = lipgloss.NewStyle().
				Padding(0, 2, 0, 0).
				Foreground(lipgloss.Color("#00FF00"))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#333333"))

	// Success / error styles.
	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00BFFF"))

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	dimmedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	// Selected checkbox.
	checkboxSelected = "◉"
	checkboxEmpty    = "◯"

	// Version arrow.
	versionArrow = "→"

	// Status markers.
	markerSuccess = "✓"
	markerError   = "✗"
	markerSkipped = "○"
	markerPending = "⟳"
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
