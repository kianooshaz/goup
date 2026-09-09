package security

import (
	"golang.org/x/mod/semver"
)

// semverCompare compares two Go module versions with the golang.org/x/mod
// semver package, tolerating missing "v" prefixes. Unparsable versions fall
// back to plain string comparison.
func semverCompare(a, b string) int {
	ca, cb := canonical(a), canonical(b)
	if ca == "" || cb == "" {
		// Not valid semver; best-effort string comparison keeps behavior
		// deterministic rather than returning an arbitrary ordering.
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		default:
			return 0
		}
	}
	return semver.Compare(ca, cb)
}

// canonical normalizes a version for semver comparison, adding the "v"
// prefix if missing. Returns "" when the version is not valid semver.
func canonical(v string) string {
	if v == "" {
		return ""
	}
	if v[0] == 'v' {
		return semver.Canonical(v)
	}
	return semver.Canonical("v" + v)
}
