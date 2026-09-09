package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// osvAPIBase is the official OSV ecosystem API. It serves the Go
	// vulnerability database (curated by the Go security team) plus GHSA
	// records for Go modules. Queries contain only package name and version.
	osvAPIBase = "https://api.osv.dev/v1"

	// osvEcosystem is the OSV ecosystem identifier for Go modules.
	osvEcosystem = "Go"

	// osvTimeout bounds a single HTTP round trip to the OSV API.
	osvTimeout = 10 * time.Second
)

// OSVProvider implements Provider against api.osv.dev.
type OSVProvider struct {
	client *http.Client
	base   string
}

// NewOSVProvider creates an OSV-backed provider.
func NewOSVProvider() *OSVProvider {
	return &OSVProvider{
		client: &http.Client{Timeout: osvTimeout},
		base:   osvAPIBase,
	}
}

// NewOSVProviderWithClient allows tests to inject a custom HTTP client
// (e.g. one backed by an httptest.Server).
func NewOSVProviderWithClient(c *http.Client, base string) *OSVProvider {
	return &OSVProvider{
		client: c,
		base:   base,
	}
}

// osvQuery is the request body for POST /v1/query.
type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvQueryResponse is the response for POST /v1/query.
type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// osvVuln is the subset of the OSV schema goup consumes.
type osvVuln struct {
	ID               string        `json:"id"`
	Summary          string        `json:"summary"`
	Details          string        `json:"details"`
	Severity         []osvSev      `json:"severity"`
	Affected         []osvAffected `json:"affected"`
	DatabaseSpecific *struct {
		Severity string `json:"severity"`
		URL      string `json:"url"`
	} `json:"database_specific"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Check queries OSV for vulnerabilities affecting module at version.
func (p *OSVProvider) Check(ctx context.Context, module, version string) ([]Vulnerability, error) {
	vulns, err := p.queryOSV(ctx, module, version)
	if err != nil {
		return nil, err
	}
	return convertVulns(vulns, module), nil
}

// queryOSV performs the HTTP query against the OSV API.
func (p *OSVProvider) queryOSV(ctx context.Context, module, version string) ([]osvVuln, error) {
	body, err := json.Marshal(osvQuery{
		Package: osvPackage{Name: module, Ecosystem: osvEcosystem},
		Version: strings.TrimPrefix(version, "v"),
	})
	if err != nil {
		return nil, fmt.Errorf("encoding OSV query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/query", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV query returned status %d", resp.StatusCode)
	}

	var parsed osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}
	return parsed.Vulns, nil
}

// convertVulns maps OSV records to the Vulnerability model, filtered to
// the queried module. Records whose affected list does not reference the
// module are dropped. Severity comes from, in order: CVSS vector, vendor
// string in database_specific, or SeverityUnknown when neither is present
// — never a guess.
func convertVulns(vulns []osvVuln, module string) []Vulnerability {
	var result []Vulnerability
	seen := make(map[string]bool)

	for _, v := range vulns {
		if seen[v.ID] {
			continue
		}
		if !affectsModule(v, module) {
			continue
		}
		seen[v.ID] = true

		vuln := Vulnerability{
			ID:          v.ID,
			Summary:     v.Summary,
			Severity:    severityFor(v),
			FixedIn:     fixedVersion(v, module),
			MoreInfoURL: moreInfoURL(v),
		}
		result = append(result, vuln)
	}
	return result
}

// affectsModule reports whether the record's affected list references the
// given Go module.
func affectsModule(v osvVuln, module string) bool {
	for _, a := range v.Affected {
		if a.Package.Name == module && a.Package.Ecosystem == osvEcosystem {
			return true
		}
	}
	return false
}

// severityFor derives the Severity from OSV severity data. GHSA records
// carry CVSS vectors; Go vulndb records (GO-...) typically carry none, in
// which case any vendor severity string is used, and otherwise the result
// is SeverityUnknown.
func severityFor(v osvVuln) Severity {
	m := SeverityMapping{}
	for _, s := range v.Severity {
		switch s.Type {
		case "CVSS_V3":
			if sev := m.FromCVSSVector(s.Score); sev != SeverityUnknown {
				return sev
			}
		}
	}
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		if sev := m.FromVendorString(v.DatabaseSpecific.Severity); sev != SeverityUnknown {
			return sev
		}
	}
	return SeverityUnknown
}

// fixedVersion extracts the first SEMVER fixed event for the queried module
// from the affected ranges. Empty when no fix is known.
func fixedVersion(v osvVuln, module string) string {
	for _, a := range v.Affected {
		if a.Package.Name != module || a.Package.Ecosystem != osvEcosystem {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					return "v" + strings.TrimPrefix(e.Fixed, "v")
				}
			}
		}
	}
	return ""
}

// moreInfoURL picks the advisory URL: database_specific first, then the
// canonical OSV web URL.
func moreInfoURL(v osvVuln) string {
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.URL != "" {
		return v.DatabaseSpecific.URL
	}
	if strings.HasPrefix(v.ID, "GHSA-") {
		return "https://github.com/advisories/" + v.ID
	}
	if strings.HasPrefix(v.ID, "GO-") {
		return "https://pkg.go.dev/vuln/" + v.ID
	}
	return ""
}
