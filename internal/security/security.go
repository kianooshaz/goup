// Package security provides dependency vulnerability checking for goup.
//
// The core abstraction is the Provider interface: anything that can answer
// "what known vulnerabilities affect this module at this version?" The
// default implementation queries the OSV ecosystem API (api.osv.dev), which
// serves the official Go vulnerability database curated by the Go security
// team. Requests contain only module paths and versions — never source code.
//
// A deep call-graph reachability scan (govulncheck) is deliberately not part
// of v1; the Reachability type models it so it can be added later without
// breaking the provider contract.
package security

// Severity is a small, fixed set of vulnerability severity levels mapped
// from the underlying data source (CVSS scores / vendor severity strings).
type Severity int

const (
	// SeverityUnknown means severity could not be reliably determined.
	SeverityUnknown Severity = iota
	// SeverityNone means no known vulnerabilities affect the module.
	SeverityNone
	// SeverityLow maps to CVSS 0.1–3.9 / vendor "LOW".
	SeverityLow
	// SeverityMedium maps to CVSS 4.0–6.9 / vendor "MODERATE".
	SeverityMedium
	// SeverityHigh maps to CVSS 7.0–8.9 / vendor "HIGH".
	SeverityHigh
	// SeverityCritical maps to CVSS 9.0–10.0 / vendor "CRITICAL".
	SeverityCritical
)

// String returns the display label for a severity. Callers render colors
// and icons in the UI layer; this returns the plain word only.
func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "NO KNOWN ISSUES"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Rank orders severities by seriousness for sorting and max-computation.
// Unknown ranks lowest so it never outranks a real signal, and never
// outranks SeverityNone when deciding "is anything wrong here?".
func (s Severity) Rank() int {
	switch s {
	case SeverityNone:
		return 1
	case SeverityUnknown:
		return 0
	default:
		return int(s) // Low=2 ... Critical=5
	}
}

// Reachability describes whether vulnerable code is actually called from
// the application. The lightweight module-level scan cannot know this;
// only a deep call-graph analysis (govulncheck) can.
type Reachability int

const (
	// ReachabilityUnknown means no reachability analysis was performed.
	ReachabilityUnknown Reachability = iota
	// ReachabilityReachable means a call path from the application to
	// vulnerable code was found.
	ReachabilityReachable
	// ReachabilityDependencyOnly means vulnerable code exists in the
	// dependency graph but is not called.
	ReachabilityDependencyOnly
)

// String returns the display label for a reachability state.
func (r Reachability) String() string {
	switch r {
	case ReachabilityReachable:
		return "reachable"
	case ReachabilityDependencyOnly:
		return "dependency-only"
	default:
		return "unknown"
	}
}

// Vulnerability is a single known vulnerability affecting a module version.
type Vulnerability struct {
	// ID is the database identifier, e.g. "GO-2023-1737" or "GHSA-...". Aliases
	// (CVE) are not stored separately; the ID links to the full record.
	ID string
	// Summary is a one-line human-readable description.
	Summary string
	// Severity is the mapped severity level (SeverityUnknown when the source
	// provides no usable severity data).
	Severity Severity
	// FixedIn is the first version where the vulnerability is fixed,
	// empty when no fix is known.
	FixedIn string
	// MoreInfoURL links to the full advisory.
	MoreInfoURL string
}

// Status is the overall security state of one dependency.
type Status struct {
	// Vulnerabilities lists every known vulnerability affecting the current
	// version, empty when none are known.
	Vulnerabilities []Vulnerability
	// Severity is the worst severity among the vulnerabilities. For an empty
	// list it is SeverityNone. It is SeverityUnknown only when checking could
	// not be performed (see Checked).
	Severity Severity
	// Reachability is ReachabilityUnknown unless a deep scan ran.
	Reachability Reachability
	// Checked reports whether the security check actually completed. When
	// false, an empty vulnerability list means "could not check", NOT
	// "no known issues" — the UI must render an availability warning rather
	// than a clean bill of health.
	Checked bool
	// Err carries the failure reason when Checked is false.
	Err error
}

// CheckedOK reports whether the check completed without error.
func (s Status) CheckedOK() bool {
	return s.Checked && s.Err == nil
}

// SeverityFor returns the severity for a set of vulnerabilities, or
// SeverityNone when the set is empty. Returns SeverityUnknown only when
// explicitly passed as an input.
func worstSeverity(vulns []Vulnerability) Severity {
	if len(vulns) == 0 {
		return SeverityNone
	}
	worst := SeverityUnknown
	for _, v := range vulns {
		if v.Severity.Rank() > worst.Rank() {
			worst = v.Severity
		}
	}
	return worst
}

// FixAssessment answers the product question: does the currently available
// upgrade resolve the known vulnerabilities? It is computed against the
// concrete fixed versions — never against "latest is newest, so it must be
// safe".
type FixAssessment int

const (
	// FixUnknown means no vulnerabilities exist, or the assessment cannot
	// be computed (e.g. unparsable versions, no upgrade target).
	FixUnknown FixAssessment = iota
	// FixResolved means every vulnerability is fixed at or below the upgrade
	// target: upgrading resolves all known issues.
	FixResolved
	// FixPartial means some vulnerabilities are fixed by the upgrade but at
	// least one remains (or its fix status cannot be determined).
	FixPartial
	// FixUnresolved means none of the vulnerabilities are fixed by the
	// available upgrade.
	FixUnresolved
	// FixNoneAvailable means there is no fixed version known for at least one
	// vulnerability, so no upgrade target can be verified.
	FixNoneAvailable
)

// AssessFix determines whether upgrading from current to target resolves
// the given vulnerabilities. It is a pure function so it is fully unit
// testable without any provider.
func AssessFix(current, target string, vulns []Vulnerability) FixAssessment {
	if len(vulns) == 0 {
		return FixUnknown
	}
	if target == "" {
		return FixUnknown
	}

	resolved := 0
	unresolved := 0
	noFixKnown := 0

	for _, v := range vulns {
		switch {
		case v.FixedIn == "":
			noFixKnown++
		case versionAtOrAfter(target, v.FixedIn):
			resolved++
		default:
			unresolved++
		}
	}

	switch {
	case resolved == 0 && unresolved == 0 && noFixKnown > 0:
		return FixNoneAvailable
	case resolved > 0 && unresolved > 0:
		return FixPartial
	case resolved > 0 && noFixKnown > 0:
		return FixPartial
	case unresolved > 0:
		return FixUnresolved
	case resolved > 0:
		return FixResolved
	default:
		return FixUnknown
	}
}

// FixAssessmentString returns the display label for a fix assessment.
func FixAssessmentString(f FixAssessment) string {
	switch f {
	case FixResolved:
		return "Upgrade fixes security issue"
	case FixPartial:
		return "Upgrade does not fully fix vulnerability"
	case FixUnresolved:
		return "Upgrade does not fix vulnerability"
	case FixNoneAvailable:
		return "No fixed version available"
	default:
		return ""
	}
}

// versionAtOrAfter reports whether v >= baseline using semantic version
// comparison. If either version is not valid semver the answer is
// conservatively false: an unparsable version must never be claimed to
// resolve a vulnerability.
func versionAtOrAfter(v, baseline string) bool {
	if baseline == "" || v == "" {
		return false
	}
	if canonical(v) == "" || canonical(baseline) == "" {
		return false
	}
	return semverCompare(v, baseline) >= 0
}
