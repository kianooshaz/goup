package module

import (
	"golang.org/x/mod/semver"
)

// ClassifyUpdate determines the type of update between current and latest versions.
//
// It handles:
//   - Standard semantic versions (v1.2.3)
//   - v0.x versions (treated as unstable; any v0.x → v0.y update is UpdateMinor,
//     v0.x → v1.y is UpdateMajor)
//   - Pseudo-versions (v0.0.0-202…)
//   - Pre-release versions (v1.2.3-alpha)
//   - Major version suffixes (/v2, /v3, etc.)
//
// If the versions cannot be classified, UpdateUnknown is returned.
func ClassifyUpdate(current, latest string) UpdateType {
	if current == "" || latest == "" {
		return UpdateUnknown
	}

	// Ensure both have "v" prefix for semver package.
	cur := semver.Canonical(current)
	lat := semver.Canonical(latest)

	if cur == "" || lat == "" {
		// One or both are not valid semantic versions (e.g., pseudo-versions
		// without a base tag). Fall back to string comparison.
		return fallbackClassify(current, latest)
	}

	cmp := semver.Compare(cur, lat)
	if cmp >= 0 {
		// Current is already at or ahead of "latest" (shouldn't normally
		// happen in the update list, but be defensive).
		return UpdateUnknown
	}

	curMajor := semver.Major(cur)
	latMajor := semver.Major(lat)

	if curMajor != latMajor {
		return UpdateMajor
	}

	curMajorMinor := semver.MajorMinor(cur)
	latMajorMinor := semver.MajorMinor(lat)

	if curMajorMinor != latMajorMinor {
		return UpdateMinor
	}

	// Same major.minor — must be a patch update.
	// But check if current is a pre-release of the same version.
	curPre := semver.Prerelease(cur)
	latPre := semver.Prerelease(lat)

	if curPre != "" && latPre == "" {
		// Current is a pre-release of the stable version.
		return UpdatePatch
	}

	// Same major.minor.patch but current has a different pre-release? Unusual.
	return UpdatePatch
}

// fallbackClassify handles edge cases where semver.Canonical fails.
func fallbackClassify(current, latest string) UpdateType {
	// If either is a pseudo-version (contains a timestamp), we can't reliably
	// classify. Just return unknown.
	if isPseudoVersion(current) || isPseudoVersion(latest) {
		return UpdateUnknown
	}

	// Try basic semver parsing manually.
	curMaj, curMin, curPat := parseVersionParts(current)
	latMaj, latMin, latPat := parseVersionParts(latest)

	if curMaj < 0 || latMaj < 0 {
		return UpdateUnknown
	}

	if curMaj != latMaj {
		return UpdateMajor
	}
	if curMin != latMin {
		return UpdateMinor
	}
	if curPat != latPat {
		return UpdatePatch
	}
	return UpdateUnknown
}

// isPseudoVersion returns true if v looks like a Go pseudo-version
// (vX.Y.Z-YYYYMMDDHHMMSS-abcdefabcdef).
func isPseudoVersion(v string) bool {
	if len(v) < 20 {
		return false
	}
	// Pseudo-versions have a hyphen followed by at least 14 digits (timestamp).
	// We use a simple heuristic.
	dashCount := 0
	for _, c := range v {
		if c == '-' {
			dashCount++
		}
	}
	return dashCount >= 2
}

// parseVersionParts attempts to extract major, minor, patch from a version string.
// Returns -1 for any part that cannot be parsed.
func parseVersionParts(v string) (major, minor, patch int) {
	major, minor, patch = -1, -1, -1

	cleaned := v
	// Strip leading "v" or "V".
	if len(cleaned) > 0 && (cleaned[0] == 'v' || cleaned[0] == 'V') {
		cleaned = cleaned[1:]
	}

	// Strip pre-release suffix (e.g., "-alpha" from "1.2.3-alpha").
	if idx := indexByte(cleaned, '-'); idx >= 0 {
		cleaned = cleaned[:idx]
	}

	// Strip build metadata.
	if idx := indexByte(cleaned, '+'); idx >= 0 {
		cleaned = cleaned[:idx]
	}

	parts := splitN(cleaned, '.', 3)
	if len(parts) < 1 {
		return
	}

	major = parseInt(parts[0])
	if len(parts) < 2 {
		return
	}
	minor = parseInt(parts[1])
	if len(parts) < 3 {
		return
	}
	patch = parseInt(parts[2])
	return
}

// indexByte returns the index of the first occurrence of c in s, or -1.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// splitN splits a string by a byte separator, returning at most n parts.
func splitN(s string, sep byte, n int) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s) && len(parts) < n-1; i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// parseInt parses a non-negative integer from a string, returning -1 on failure.
func parseInt(s string) int {
	if len(s) == 0 {
		return -1
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
