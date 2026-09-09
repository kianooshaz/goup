package tui

import (
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Search state lives entirely in the TUI layer: query is the current
// search text, searching is true while the input has focus. Filtering
// operates on the in-memory dependency list only — no discovery, network,
// or vulnerability-database activity happens per keystroke.

// enterSearch activates search mode, showing the input line.
func (m *Model) enterSearch() {
	m.searching = true
}

// handleSearchKey processes keyboard input while the search input has
// focus. Printable characters (including q, a, n) are inserted into the
// query; only navigation, selection, and the exit keys keep special
// meaning. Global shortcuts resume when search mode exits.
func (m *Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case "esc":
		// Clear the query and exit search mode, restoring the full list.
		m.query = ""
		m.searching = false
		m.rebuildVisible()
		return m, nil

	case "enter":
		// Exit search mode, keeping the applied filter.
		m.searching = false
		return m, nil

	case "backspace", "ctrl+h":
		if r := []rune(m.query); len(r) > 0 {
			m.query = string(r[:len(r)-1])
			m.rebuildVisible()
		}

	case "up":
		if m.cursor > 0 {
			m.cursor--
			m.ensureCursorVisible()
		}

	case "down":
		if m.cursor < len(m.visible)-1 {
			m.cursor++
			m.ensureCursorVisible()
		}

	case " ":
		// Selection stays available while searching so the user can act
		// on filtered results directly.
		m.toggleSelection(m.cursor)

	default:
		if runes := msg.Runes; len(runes) > 0 {
			m.query += string(runes)
			m.rebuildVisible()
		}
	}
	return m, nil
}

// rebuildVisible is defined in model.go; the search stage below documents
// its ordering: security-only filter, then search filter, then security
// urgency, then prefix ranking — each stable over the previous.

// applySearchFilter appends to dst the indices of deps whose module path
// contains query (case-insensitive substring). An empty query matches
// everything.
func (m *Model) applySearchFilter(dst []int, query string) []int {
	if query == "" {
		for i := range m.deps {
			dst = append(dst, i)
		}
		return dst
	}
	q := strings.ToLower(query)
	for i := range m.deps {
		if strings.Contains(strings.ToLower(m.deps[i].Path), q) {
			dst = append(dst, i)
		}
	}
	return dst
}

// searchRank orders matches by the position of the first occurrence of
// the query in the path: earlier matches rank higher, so a path whose
// segment starts with the query beats one where it appears buried deeper
// ("github.com/redis/go-redis" ranks above "github.com/foo/redis-wrapper"
// for query "redis"). Deliberately simple — no fuzzy scoring until it
// proves its UX value; swapping this function for a richer ranker is the
// only change a future fuzzy search needs.
func searchRank(query, path string) int {
	if query == "" {
		return 0
	}
	idx := strings.Index(strings.ToLower(path), query)
	if idx < 0 {
		return int(^uint(0) >> 1) // max int: no match sorts last
	}
	return idx
}

// rankBySearch applies the prefix-before-substring ordering to the
// filtered list. Stable, so equal-rank rows keep their prior order.
func (m *Model) rankBySearch(query string) {
	if query == "" {
		return
	}
	q := strings.ToLower(query)
	sort.SliceStable(m.visible, func(a, b int) bool {
		return searchRank(q, m.deps[m.visible[a]].Path) <
			searchRank(q, m.deps[m.visible[b]].Path)
	})
}

// searchActive reports whether a search filter is applied (input focused
// or a query is in effect).
func (m *Model) searchActive() bool {
	return m.searching || m.query != ""
}
