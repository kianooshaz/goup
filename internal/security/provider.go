package security

import (
	"context"
)

// Provider is the vulnerability data source abstraction. Implementations
// answer "which known vulnerabilities affect this module at this version?"
// using only module paths and versions — never source code or project
// contents. This is the same privacy contract as the official Go
// vulnerability tooling.
//
// Implementations must honor ctx cancellation.
type Provider interface {
	// Check returns the vulnerabilities affecting module at version. A
	// successful empty result means the database was reachable and reports
	// no known vulnerabilities — it must be distinguishable from a failed
	// check (error return).
	Check(ctx context.Context, module, version string) ([]Vulnerability, error)
}

// SeverityMapping maps a source severity representation (CVSS vector,
// vendor string) into the small Severity vocabulary. It is exported so
// alternate providers can share the standard mapping.
type SeverityMapping struct{}

// FromCVSS maps a CVSS v3 base score (0.0–10.0) to Severity.
func (SeverityMapping) FromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// FromCVSSVector extracts the base score from a CVSS v3 vector string such
// as "CVSS:3.1/AV:N/AC:L/..." and maps it to Severity. Returns
// SeverityUnknown for unparsable input.
func (m SeverityMapping) FromCVSSVector(vector string) Severity {
	score, ok := cvssBaseScore(vector)
	if !ok {
		return SeverityUnknown
	}
	return m.FromCVSS(score)
}

// FromVendorString maps common vendor severity labels to Severity. Case-
// insensitive; unknown labels map to SeverityUnknown rather than guessing.
func (SeverityMapping) FromVendorString(s string) Severity {
	switch normalizeLabel(s) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH", "IMPORTANT":
		return SeverityHigh
	case "MODERATE", "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "NONE", "INFORMATIONAL":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
