package security

import (
	"math"
	"strings"
)

// normalizeLabel uppercases and trims a vendor severity label.
func normalizeLabel(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// cvssBaseScore parses a CVSS v3 base score out of an OSV severity vector
// such as "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", applying the
// v3.1 base-score formula. Returns ok=false for unparsable or incomplete
// vectors so callers can fall back to SeverityUnknown instead of guessing.
func cvssBaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:") {
		return 0, false
	}

	var av, ac, pr, ui, scope, c, i, a string
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "AV":
			av = kv[1]
		case "AC":
			ac = kv[1]
		case "PR":
			pr = kv[1]
		case "UI":
			ui = kv[1]
		case "S":
			scope = kv[1]
		case "C":
			c = kv[1]
		case "I":
			i = kv[1]
		case "A":
			a = kv[1]
		}
	}
	if av == "" || ac == "" || pr == "" || ui == "" || scope == "" ||
		c == "" || i == "" || a == "" {
		return 0, false
	}

	// Metric weights from the CVSS v3.1 specification, Table 16.
	avW, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[av]
	if !ok {
		return 0, false
	}
	acW, ok := map[string]float64{"L": 0.77, "H": 0.44}[ac]
	if !ok {
		return 0, false
	}
	uiW, ok := map[string]float64{"N": 0.85, "R": 0.62}[ui]
	if !ok {
		return 0, false
	}

	var prW float64
	switch pr {
	case "N":
		prW = 0.85
	case "L":
		if scope == "C" {
			prW = 0.68
		} else {
			prW = 0.62
		}
	case "H":
		if scope == "C" {
			prW = 0.5
		} else {
			prW = 0.27
		}
	default:
		return 0, false
	}

	ciaW := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	cW, ok := ciaW[c]
	if !ok {
		return 0, false
	}
	iW, ok := ciaW[i]
	if !ok {
		return 0, false
	}
	aW, ok := ciaW[a]
	if !ok {
		return 0, false
	}

	// ISS = 1 - (1-C)(1-I)(1-A)
	iss := 1 - (1-cW)*(1-iW)*(1-aW)

	var impact float64
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * avW * acW * prW * uiW
	score := impact + exploitability
	if scope == "C" {
		score *= 1.08
	}
	return round1(min10(score)), true
}

// min10 clamps a CVSS score to 10.0.
func min10(v float64) float64 {
	if v > 10 {
		return 10
	}
	return v
}

// round1 rounds to one decimal place per the CVSS specification.
func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
