package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/kianooshaz/goup/internal/security"
)

// Severity icons and colors. Only the worst issue of a dependency is shown
// on the main list row to keep it scannable; the detail view breaks it down.
var severityBadges = map[security.Severity]struct {
	icon  string
	color lipgloss.Color
}{
	security.SeverityCritical: {icon: "🔴", color: lipgloss.Color("#FF3B30")},
	security.SeverityHigh:     {icon: "🟠", color: lipgloss.Color("#FF9500")},
	security.SeverityMedium:   {icon: "🟡", color: lipgloss.Color("#FFD60A")},
	security.SeverityLow:      {icon: "🔵", color: lipgloss.Color("#0A84FF")},
}

// severityBadge renders "🔴 CRITICAL"-style text for a severity. For
// SeverityNone it renders a quiet checkmark; for SeverityUnknown a dimmed
// question mark. Multiple vulnerabilities get a count, e.g. "🔴 HIGH (3)".
func severityBadge(sev security.Severity, count int) string {
	if sev == security.SeverityNone {
		return dimmedStyle.Render("✓")
	}
	if sev == security.SeverityUnknown {
		return mutedStyle.Render("⚪ UNKNOWN")
	}

	badge, ok := severityBadges[sev]
	if !ok {
		return mutedStyle.Render("⚪ UNKNOWN")
	}

	label := sev.String()
	if count > 1 {
		label = fmt.Sprintf("%s (%d)", label, count)
	}
	style := lipgloss.NewStyle().Foreground(badge.color)
	return style.Render(badge.icon + " " + label)
}

// severityBadgeCompact renders just "🔴 1" — the icon plus a count — for
// the header summary line where the full label would be too wide.
func severityBadgeCompact(sev security.Severity, count int) string {
	badge, ok := severityBadges[sev]
	if !ok {
		return mutedStyle.Render(fmt.Sprintf("⚪ %d", count))
	}
	return lipgloss.NewStyle().Foreground(badge.color).Render(
		fmt.Sprintf("%s %d", badge.icon, count))
}

// securityColumn renders the security column for a dependency row,
// including the reachability/known-vulnerability qualifier:
//
//	🔴 HIGH  reachable        (deep scan ran — future use)
//	🔴 HIGH  known vulnerability (lightweight scan — always in v1)
func securityColumn(item security.DependencyStatus) string {
	st := item.Status

	if !st.Checked {
		// Check failed or was skipped (private module). Never render this
		// as "secure".
		reason := "security check failed"
		if st.Err != nil && strings.Contains(st.Err.Error(), security.ErrPrivateModule.Error()) {
			reason = "private module: not checked"
		}
		return warningStyle.Render("⚠ " + reason)
	}

	if len(st.Vulnerabilities) == 0 {
		return severityBadge(st.Severity, 0)
	}

	badge := severityBadge(st.Severity, len(st.Vulnerabilities))
	// v1 always uses the lightweight scan, so reachability is unknown and
	// we say "known vulnerability" rather than implying exploitability was
	// verified. A deep govulncheck pass would swap in Reachability labels.
	if st.Reachability != security.ReachabilityUnknown {
		return badge + dimmedStyle.Render("  "+st.Reachability.String())
	}
	return badge
}

// fixNote renders a short remediation hint for the row, only when it adds
// signal beyond the badge (i.e. when there are vulnerabilities).
func fixNote(item security.DependencyStatus) string {
	if !item.Status.CheckedOK() || len(item.Status.Vulnerabilities) == 0 {
		return ""
	}
	switch item.Fix {
	case security.FixResolved:
		return successStyle.Render("✓ fixed by upgrade")
	case security.FixPartial:
		return warningStyle.Render("⚠ partially fixed by upgrade")
	case security.FixUnresolved:
		return warningStyle.Render("⚠ upgrade does not fix")
	case security.FixNoneAvailable:
		return warningStyle.Render("⚠ no fix available")
	default:
		return ""
	}
}

// SecuritySummary aggregates the headline numbers for the list header:
// how many dependencies have issues, broken down by severity.
type SecuritySummary struct {
	// TotalVulnerable is the number of dependencies with at least one
	// confirmed vulnerability.
	TotalVulnerable int
	// BySeverity counts vulnerable dependencies per severity.
	BySeverity map[security.Severity]int
	// FailedChecks counts dependencies whose security check could not be
	// performed (network failure, private module).
	FailedChecks int
}

// Summarize aggregates dependency statuses into a SecuritySummary.
func Summarize(items []security.DependencyStatus) SecuritySummary {
	s := SecuritySummary{BySeverity: make(map[security.Severity]int)}
	for _, it := range items {
		if !it.Status.CheckedOK() {
			s.FailedChecks++
			continue
		}
		if len(it.Status.Vulnerabilities) > 0 {
			s.TotalVulnerable++
			s.BySeverity[it.Status.Severity]++
		}
	}
	return s
}

// HasIssues reports whether the summary warrants a headline line.
func (s SecuritySummary) HasIssues() bool {
	return s.TotalVulnerable > 0 || s.FailedChecks > 0
}

// Render produces the compact header summary, e.g.:
//
//	2 security fixes  🔴 1  🟠 1
//	⚠ 1 dependency could not be checked
func (s SecuritySummary) Render() string {
	if s.TotalVulnerable > 0 {
		var parts []string
		// Order: most severe first.
		for _, sev := range []security.Severity{
			security.SeverityCritical,
			security.SeverityHigh,
			security.SeverityMedium,
			security.SeverityLow,
			security.SeverityUnknown,
		} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, severityBadgeCompact(sev, n))
			}
		}
		line := fmt.Sprintf("%d security fixes  %s", s.TotalVulnerable, strings.Join(parts, "  "))
		out := line
		if s.FailedChecks > 0 {
			out += "\n" + warningStyle.Render(fmt.Sprintf("⚠ %d dependencies could not be checked", s.FailedChecks))
		}
		return out
	}
	if s.FailedChecks > 0 {
		return warningStyle.Render(fmt.Sprintf("⚠ %d dependencies could not be checked", s.FailedChecks))
	}
	return ""
}

// detailView renders the full security detail screen for one dependency:
// every vulnerability individually, with affected ranges and the fix
// assessment. Keyed with "d" from the list; Esc returns. The list key
// handler only opens this screen when security data is present, so the
// out-of-range branch is a defensive guard rather than a reachable state.
func (m *Model) detailView() string {
	if m.detailIndex < 0 || m.detailIndex >= len(m.security) {
		return appStyle.Render(titleStyle.Render("\n  Security details") +
			"\n\n" +
			dimmedStyle.Render("  No security information available for this dependency.") +
			fmt.Sprintf("\n\n  %s  %s\n", infoStyle.Render("Esc/d"), dimmedStyle.Render("Back")))
	}
	item := m.security[m.detailIndex]
	dep := item.Dependency

	var b strings.Builder
	b.WriteString(titleStyle.Render("\n  Security details"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  %s\n", dep.Path))
	b.WriteString(fmt.Sprintf("  %s %s\n",
		dimmedStyle.Render("Current version:"),
		dep.CurrentVersion))

	if dep.Indirect {
		b.WriteString(fmt.Sprintf("  %s\n", dimmedStyle.Render("indirect dependency")))
	}
	b.WriteString("\n")

	switch {
	case !item.Status.CheckedOK():
		reason := "The vulnerability database could not be reached."
		if item.Status.Err != nil {
			reason = item.Status.Err.Error()
		}
		b.WriteString(warningStyle.Render("  ⚠ Security information unavailable") + "\n\n")
		b.WriteString(dimmedStyle.Render("  "+reason) + "\n")
	case len(item.Status.Vulnerabilities) == 0:
		b.WriteString(successStyle.Render("  ✓ No known vulnerabilities") + "\n")
	default:
		for i, v := range item.Status.Vulnerabilities {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString("  " + severityBadge(v.Severity, 1) + "  " + v.ID + "\n")
			if v.Summary != "" {
				b.WriteString(dimmedStyle.Render("  "+wrapText(v.Summary, m.width-6, 4)) + "\n")
			}
			if v.FixedIn != "" {
				b.WriteString(fmt.Sprintf("  %s %s\n", dimmedStyle.Render("Fixed in:"), successStyle.Render(v.FixedIn)))
			} else {
				b.WriteString(fmt.Sprintf("  %s %s\n", dimmedStyle.Render("Fixed in:"), warningStyle.Render("no fixed version known")))
			}
			if v.MoreInfoURL != "" {
				b.WriteString(fmt.Sprintf("  %s %s\n", dimmedStyle.Render("More info:"), v.MoreInfoURL))
			}
		}

		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s %s\n",
			dimmedStyle.Render("Available upgrade:"),
			dep.LatestVersion))

		switch item.Fix {
		case security.FixResolved:
			b.WriteString(successStyle.Render("  ✓ Upgrading this dependency resolves the known vulnerabilities.") + "\n")
		case security.FixPartial:
			b.WriteString(warningStyle.Render("  ⚠ Upgrading fixes some, but not all, known vulnerabilities.") + "\n")
		case security.FixUnresolved:
			b.WriteString(warningStyle.Render("  ⚠ Upgrading does not fix the known vulnerabilities.") + "\n")
		case security.FixNoneAvailable:
			b.WriteString(warningStyle.Render("  ⚠ No fixed version is known yet.") + "\n")
		default:
			b.WriteString(dimmedStyle.Render("  ? Unable to determine whether the upgrade fixes these issues.") + "\n")
		}
	}

	b.WriteString(fmt.Sprintf("\n  %s  %s\n",
		infoStyle.Render("Esc/d"),
		dimmedStyle.Render("Back"),
	))
	return appStyle.Render(b.String())
}

// wrapText hard-wraps s to width, indenting continuation lines by indent
// spaces. Words longer than width are not broken.
func wrapText(s string, width, indent int) string {
	if width <= indent+8 {
		return s
	}
	avail := width - indent
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case len(cur)+1+len(w) <= avail:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	pad := strings.Repeat(" ", indent)
	for i := range lines {
		if i > 0 {
			lines[i] = pad + lines[i]
		}
	}
	return strings.Join(lines, "\n  ")
}
