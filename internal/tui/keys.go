package tui

// keyMap defines all key bindings used in the TUI.
type keyMap struct{}

func (k keyMap) help() []keyBinding {
	return []keyBinding{
		{key: "↑/↓", desc: "Navigate"},
		{key: "j/k", desc: "Navigate"},
		{key: "Space", desc: "Select"},
		{key: "a", desc: "All"},
		{key: "n", desc: "None"},
		{key: "Enter", desc: "Upgrade"},
		{key: "q/Esc", desc: "Quit"},
	}
}

type keyBinding struct {
	key  string
	desc string
}

// Matches returns true if the tea.KeyMsg matches this binding.
// We handle this in the model's Update rather than here.
