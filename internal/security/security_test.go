package security

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kianooshaz/goup/internal/module"
)

// fakeProvider is a scriptable Provider for tests: no network involved.
type fakeProvider struct {
	mu     sync.Mutex
	byMod  map[string][]Vulnerability // module -> vulns (matched regardless of version)
	err    error
	called []string
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{byMod: make(map[string][]Vulnerability)}
}

func (f *fakeProvider) add(module string, vulns ...Vulnerability) {
	f.byMod[module] = append(f.byMod[module], vulns...)
}

func (f *fakeProvider) failWith(err error) { f.err = err }

func (f *fakeProvider) Check(_ context.Context, m, v string) ([]Vulnerability, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, m+"@"+v)
	if f.err != nil {
		return nil, f.err
	}
	return f.byMod[m], nil
}

var (
	vulnHigh      = Vulnerability{ID: "GO-2026-1111", Summary: "s", Severity: SeverityHigh, FixedIn: "v1.4.5", MoreInfoURL: "https://pkg.go.dev/vuln/GO-2026-1111"}
	vulnCritical  = Vulnerability{ID: "GO-2026-0001", Severity: SeverityCritical, FixedIn: "v2.0.0"}
	vulnMedium    = Vulnerability{ID: "GHSA-xxxx-yyyy-zzzz", Severity: SeverityMedium, FixedIn: "v1.2.3"}
	vulnNoFix     = Vulnerability{ID: "GO-2026-2222", Severity: SeverityHigh}
	vulnUnknownSv = Vulnerability{ID: "GO-2026-3333", Severity: SeverityUnknown, FixedIn: "v9.9.9"}
)

// --- Provider / Checker scenarios ---

func TestCheckAllVulnerableDependency(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/foo/bar", vulnHigh)

	c := NewChecker(fp, nil)
	statuses := c.CheckAll(context.Background(), []Request{
		{Module: "github.com/foo/bar", Version: "v1.4.2"},
	})

	s := statuses[0]
	if !s.CheckedOK() {
		t.Fatalf("expected checked status, got err=%v", s.Err)
	}
	if len(s.Vulnerabilities) != 1 || s.Vulnerabilities[0].ID != "GO-2026-1111" {
		t.Fatalf("unexpected vulnerabilities: %+v", s.Vulnerabilities)
	}
	if s.Severity != SeverityHigh {
		t.Errorf("severity = %v, want HIGH", s.Severity)
	}
}

func TestCheckAllNonVulnerableDependency(t *testing.T) {
	fp := newFakeProvider() // nothing registered => no vulns

	c := NewChecker(fp, nil)
	statuses := c.CheckAll(context.Background(), []Request{
		{Module: "github.com/foo/clean", Version: "v1.0.0"},
	})

	s := statuses[0]
	if !s.CheckedOK() {
		t.Fatalf("expected checked status, got err=%v", s.Err)
	}
	if len(s.Vulnerabilities) != 0 {
		t.Fatalf("expected no vulnerabilities, got %+v", s.Vulnerabilities)
	}
	if s.Severity != SeverityNone {
		t.Errorf("severity = %v, want NONE", s.Severity)
	}
}

func TestCheckAllMultipleVulnerabilities(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/foo/multi", vulnCritical, vulnHigh, vulnMedium)

	c := NewChecker(fp, nil)
	statuses := c.CheckAll(context.Background(), []Request{
		{Module: "github.com/foo/multi", Version: "v1.0.0"},
	})

	s := statuses[0]
	if len(s.Vulnerabilities) != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d", len(s.Vulnerabilities))
	}
	if s.Severity != SeverityCritical {
		t.Errorf("worst severity = %v, want CRITICAL", s.Severity)
	}
}

func TestCheckAllDatabaseFailure(t *testing.T) {
	fp := newFakeProvider()
	fp.failWith(errors.New("connection refused"))

	c := NewChecker(fp, nil)
	statuses := c.CheckAll(context.Background(), []Request{
		{Module: "github.com/foo/bar", Version: "v1.0.0"},
		{Module: "github.com/foo/clean", Version: "v1.0.0"},
	})

	if statuses[0].Checked || statuses[0].Severity != SeverityUnknown {
		t.Errorf("failed check must not look checked/clean: %+v", statuses[0])
	}
	if !errors.Is(statuses[0].Err, ErrUnavailable) {
		t.Errorf("err = %v, want wrapped ErrUnavailable", statuses[0].Err)
	}
	// The failed check must never be reported as "no known issues".
	if statuses[0].Severity == SeverityNone {
		t.Error("database failure must not map to SeverityNone")
	}
}

func TestCheckAllPrivateModuleNotQueried(t *testing.T) {
	fp := newFakeProvider()

	c := NewChecker(fp, nil)
	statuses := c.CheckAll(context.Background(), []Request{
		{Module: "corp.internal/lib", Version: "v1.0.0"}, // has dot => public, queried
		{Module: "mycompany/secret", Version: "v1.0.0"},  // dotless => private, skipped
	})

	for _, called := range fp.called {
		if called == "mycompany/secret@v1.0.0" {
			t.Error("private module must not be queried")
		}
	}
	if statuses[0].Checked != true {
		t.Error("public module should be checked")
	}
	if statuses[1].Checked {
		t.Error("private module should not be reported as checked")
	}
	if statuses[1].Severity == SeverityNone {
		t.Error("skipped private module must not look like 'no known issues'")
	}
}

func TestIsPrivateModule(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"github.com/foo/bar", false},
		{"golang.org/x/sync", false},
		{"gopkg.in/yaml.v3", false},
		{"company/secret", true},
		{"bare", true},
		{"", true},
	}
	for _, tt := range tests {
		if got := IsPrivateModule(tt.path); got != tt.want {
			t.Errorf("IsPrivateModule(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// --- Fix assessment scenarios ---

func TestAssessFix(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		vulns   []Vulnerability
		want    FixAssessment
	}{
		{"upgrade fixes", "v1.4.2", "v1.4.5", []Vulnerability{vulnHigh}, FixResolved},
		{"upgrade above fix", "v1.4.2", "v1.5.0", []Vulnerability{vulnHigh}, FixResolved},
		{"latest still vulnerable", "v1.4.2", "v1.4.4", []Vulnerability{vulnHigh}, FixUnresolved},
		{"partial fix", "v1.0.0", "v1.2.3", []Vulnerability{vulnMedium, vulnHigh}, FixPartial},
		{"no fixed version", "v1.0.0", "v9.9.9", []Vulnerability{vulnNoFix}, FixNoneAvailable},
		{"no vulns", "v1.0.0", "v1.1.0", nil, FixUnknown},
		{"no target", "v1.0.0", "", []Vulnerability{vulnHigh}, FixUnknown},
		{"unparsable target", "v1.0.0", "weird", []Vulnerability{vulnHigh}, FixUnresolved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AssessFix(tt.current, tt.target, tt.vulns); got != tt.want {
				t.Errorf("AssessFix(%q, %q) = %v, want %v", tt.current, tt.target, got, tt.want)
			}
		})
	}
}

// --- Enrichment scenarios ---

func TestEnrichIndirectVulnerableDependency(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/indirect/bad", vulnHigh)

	deps := []module.Dependency{
		{Path: "github.com/direct/good", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/indirect/bad", CurrentVersion: "v1.4.2", LatestVersion: "v1.4.5", Indirect: true},
	}

	items := Enrich(context.Background(), NewChecker(fp, nil), deps)

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if len(items[1].Status.Vulnerabilities) != 1 {
		t.Errorf("indirect dependency should carry its vulnerability: %+v", items[1])
	}
	if items[1].Fix != FixResolved {
		t.Errorf("fix = %v, want FixResolved", items[1].Fix)
	}
}

func TestEnrichUnknownSeverityPreserved(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/foo/unknown", vulnUnknownSv)

	deps := []module.Dependency{
		{Path: "github.com/foo/unknown", CurrentVersion: "v1.0.0", LatestVersion: "v9.9.9"},
	}
	items := Enrich(context.Background(), NewChecker(fp, nil), deps)

	if items[0].Status.Severity != SeverityUnknown {
		t.Errorf("severity = %v, want UNKNOWN", items[0].Status.Severity)
	}
}

func TestFilterVulnerable(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/foo/vuln", vulnHigh)

	deps := []module.Dependency{
		{Path: "github.com/foo/vuln", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
	}
	items := Enrich(context.Background(), NewChecker(fp, nil), deps)

	vulns := FilterVulnerable(items)
	if len(vulns) != 1 || vulns[0].Dependency.Path != "github.com/foo/vuln" {
		t.Errorf("FilterVulnerable returned %+v, want only github.com/foo/vuln", vulns)
	}
}

func TestSortBySecurity(t *testing.T) {
	fp := newFakeProvider()
	fp.add("github.com/foo/low", Vulnerability{ID: "X", Severity: SeverityLow})
	fp.add("github.com/foo/crit", vulnCritical)

	deps := []module.Dependency{
		{Path: "github.com/foo/clean", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/low", CurrentVersion: "v1.0.0", LatestVersion: "v1.1.0"},
		{Path: "github.com/foo/crit", CurrentVersion: "v1.0.0", LatestVersion: "v2.0.0"},
	}
	items := Enrich(context.Background(), NewChecker(fp, nil), deps)
	SortBySecurity(items)

	want := []string{"github.com/foo/crit", "github.com/foo/low", "github.com/foo/clean"}
	for i, w := range want {
		if items[i].Dependency.Path != w {
			t.Errorf("position %d = %s, want %s", i, items[i].Dependency.Path, w)
		}
	}
}

// --- Cache scenarios ---

func TestDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := NewDiskCache(dir)

	if _, ok := c.Get("github.com/foo/bar", "v1.0.0"); ok {
		t.Fatal("empty cache should miss")
	}

	c.Put("github.com/foo/bar", "v1.0.0", []Vulnerability{vulnHigh})

	got, ok := c.Get("github.com/foo/bar", "v1.0.0")
	if !ok || len(got) != 1 || got[0].ID != "GO-2026-1111" {
		t.Fatalf("cache hit failed: ok=%v got=%+v", ok, got)
	}
}

func TestDiskCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	c := NewDiskCacheWithTTL(dir, -time.Hour) // already expired

	c.Put("github.com/foo/bar", "v1.0.0", []Vulnerability{vulnHigh})
	if _, ok := c.Get("github.com/foo/bar", "v1.0.0"); ok {
		t.Fatal("expired entry should miss")
	}
}

func TestCheckerUsesCache(t *testing.T) {
	fp := newFakeProvider()
	dir := t.TempDir()
	cache := NewDiskCache(dir)
	c := NewChecker(fp, cache)

	reqs := []Request{{Module: "github.com/foo/bar", Version: "v1.0.0"}}
	c.CheckAll(context.Background(), reqs)
	c.CheckAll(context.Background(), reqs)

	if n := len(fp.called); n != 1 {
		t.Errorf("provider called %d times, want 1 (second must hit cache)", n)
	}
}

// --- Severity mapping ---

func TestSeverityMapping(t *testing.T) {
	m := SeverityMapping{}

	if got := m.FromCVSS(9.8); got != SeverityCritical {
		t.Errorf("FromCVSS(9.8) = %v, want CRITICAL", got)
	}
	if got := m.FromCVSS(7.5); got != SeverityHigh {
		t.Errorf("FromCVSS(7.5) = %v, want HIGH", got)
	}
	if got := m.FromCVSS(5.0); got != SeverityMedium {
		t.Errorf("FromCVSS(5.0) = %v, want MEDIUM", got)
	}
	if got := m.FromCVSS(2.1); got != SeverityLow {
		t.Errorf("FromCVSS(2.1) = %v, want LOW", got)
	}
	if got := m.FromCVSS(0); got != SeverityUnknown {
		t.Errorf("FromCVSS(0) = %v, want UNKNOWN", got)
	}

	// Known vectors: HTTP/2 rapid reset (HIGH, 7.5) and a moderate one.
	if got := m.FromCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"); got != SeverityHigh {
		t.Errorf("rapid-reset vector = %v, want HIGH", got)
	}
	if got := m.FromCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"); got != SeverityMedium {
		t.Errorf("gin vector = %v, want MEDIUM", got)
	}
	if got := m.FromCVSSVector("garbage"); got != SeverityUnknown {
		t.Errorf("garbage vector = %v, want UNKNOWN", got)
	}
}

func TestVendorStringMapping(t *testing.T) {
	m := SeverityMapping{}
	tests := map[string]Severity{
		"CRITICAL": SeverityCritical,
		"HIGH":     SeverityHigh,
		"MODERATE": SeverityMedium,
		"MEDIUM":   SeverityMedium,
		"LOW":      SeverityLow,
		"weird":    SeverityUnknown,
		"":         SeverityUnknown,
	}
	for in, want := range tests {
		if got := m.FromVendorString(in); got != want {
			t.Errorf("FromVendorString(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	// Unknown must not outrank any real severity, and must not look clean.
	if SeverityUnknown.Rank() >= SeverityLow.Rank() {
		t.Error("UNKNOWN should rank below LOW")
	}
	if SeverityNone.Rank() <= SeverityUnknown.Rank() {
		t.Error("NONE should rank above UNKNOWN")
	}
}

// --- Semver comparison ---

func TestVersionAtOrAfter(t *testing.T) {
	tests := []struct {
		v, base string
		want    bool
	}{
		{"v1.4.5", "v1.4.5", true},
		{"v1.5.0", "v1.4.5", true},
		{"v1.4.4", "v1.4.5", false},
		{"1.5.0", "v1.4.5", true}, // missing v prefix
		{"v1.0.0", "0", true},
		{"", "v1.0.0", false},
	}
	for _, tt := range tests {
		if got := versionAtOrAfter(tt.v, tt.base); got != tt.want {
			t.Errorf("versionAtOrAfter(%q, %q) = %v, want %v", tt.v, tt.base, got, tt.want)
		}
	}
}

// --- OSV response conversion (no network) ---

func TestConvertVulns(t *testing.T) {
	osv := []osvVuln{
		{
			ID:       "GHSA-2c4m-59x9-fr2g",
			Summary:  "Session fixation in gin",
			Severity: []osvSev{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
			Affected: []osvAffected{{
				Package: osvPackage{Name: "github.com/gin-gonic/gin", Ecosystem: "Go"},
				Ranges:  []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1.9.2"}}}},
			}},
			DatabaseSpecific: &struct {
				Severity string `json:"severity"`
				URL      string `json:"url"`
			}{Severity: "MODERATE", URL: "https://github.com/advisories/GHSA-2c4m-59x9-fr2g"},
		},
		{
			ID: "GO-2023-1737",
			Affected: []osvAffected{{
				Package: osvPackage{Name: "github.com/gin-gonic/gin", Ecosystem: "Go"},
				Ranges:  []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "1.7.0"}, {Fixed: "1.9.1"}}}},
			}},
		},
		{
			// Duplicate ID must be deduplicated.
			ID: "GHSA-2c4m-59x9-fr2g",
		},
	}

	vulns := convertVulns(osv, "github.com/gin-gonic/gin")
	if len(vulns) != 2 {
		t.Fatalf("expected 2 deduplicated vulns, got %d", len(vulns))
	}

	first := vulns[0]
	if first.Severity != SeverityMedium {
		t.Errorf("CVSS vector should map to MEDIUM, got %v", first.Severity)
	}
	if first.FixedIn != "v1.9.2" {
		t.Errorf("FixedIn = %q, want v1.9.2", first.FixedIn)
	}
	if first.MoreInfoURL == "" {
		t.Error("MoreInfoURL should be populated from database_specific")
	}

	// GO- record without any severity data must be UNKNOWN, not guessed.
	if vulns[1].Severity != SeverityUnknown {
		t.Errorf("GO record without severity data = %v, want UNKNOWN", vulns[1].Severity)
	}
	if vulns[1].FixedIn != "v1.9.1" {
		t.Errorf("FixedIn = %q, want v1.9.1", vulns[1].FixedIn)
	}
}

func TestConvertVulnsOtherModuleIgnored(t *testing.T) {
	osv := []osvVuln{{
		ID: "GO-2023-1",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "github.com/other/mod", Ecosystem: "Go"},
			Ranges:  []osvRange{{Type: "SEMVER", Events: []osvEvent{{Fixed: "1.0.1"}}}},
		}},
	}}
	vulns := convertVulns(osv, "github.com/gin-gonic/gin")
	if len(vulns) != 0 {
		t.Errorf("records for other modules must be ignored, got %d", len(vulns))
	}
}

// --- Status alignment and concurrency sanity ---

func TestCheckAllPreservesOrderAndIndexes(t *testing.T) {
	fp := newFakeProvider()
	for i := 0; i < 20; i++ {
		fp.add(fmt.Sprintf("github.com/foo/mod%02d", i), vulnHigh)
	}
	var reqs []Request
	for i := 0; i < 20; i++ {
		reqs = append(reqs, Request{
			Module:  fmt.Sprintf("github.com/foo/mod%02d", i),
			Version: "v1.0.0",
		})
	}

	statuses := NewChecker(fp, nil).CheckAll(context.Background(), reqs)
	for i, s := range statuses {
		if !s.CheckedOK() || len(s.Vulnerabilities) != 1 {
			t.Errorf("statuses[%d] misaligned: %+v", i, s)
		}
	}
}

func TestWorstSeverityMixedUnknown(t *testing.T) {
	// A known HIGH plus an UNKNOWN must report HIGH (unknown must not
	// escalate or mask the real signal).
	got := worstSeverity([]Vulnerability{vulnHigh, vulnUnknownSv})
	if got != SeverityHigh {
		t.Errorf("worst = %v, want HIGH", got)
	}
}
