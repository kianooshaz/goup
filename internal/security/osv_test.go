package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// decodeJSON decodes a request body into v (test helper).
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// fakeOSVServer serves canned OSV API responses so the HTTP layer is
// tested without touching the network.
func fakeOSVServer(t *testing.T, handler http.HandlerFunc) *OSVProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewOSVProviderWithClient(srv.Client(), srv.URL)
}

func TestOSVProviderHappyPath(t *testing.T) {
	p := fakeOSVServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query" {
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-2023-1737","summary":"something","affected":[{"package":{"name":"github.com/gin-gonic/gin","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.7.0"},{"fixed":"1.9.1"}]}]}]}]}`))
	})

	vulns, err := p.Check(context.Background(), "github.com/gin-gonic/gin", "v1.8.0")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GO-2023-1737" {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}
	if vulns[0].FixedIn != "v1.9.1" {
		t.Errorf("FixedIn = %q, want v1.9.1", vulns[0].FixedIn)
	}
	if vulns[0].MoreInfoURL != "https://pkg.go.dev/vuln/GO-2023-1737" {
		t.Errorf("MoreInfoURL = %q", vulns[0].MoreInfoURL)
	}
}

func TestOSVProviderServerError(t *testing.T) {
	p := fakeOSVServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	_, err := p.Check(context.Background(), "github.com/foo/bar", "v1.0.0")
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
}

func TestOSVProviderEmptyResult(t *testing.T) {
	p := fakeOSVServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})

	vulns, err := p.Check(context.Background(), "github.com/foo/clean", "v1.0.0")
	if err != nil {
		t.Fatalf("empty result must not be an error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns, got %+v", vulns)
	}
}

func TestOSVProviderInvalidJSON(t *testing.T) {
	p := fakeOSVServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})

	if _, err := p.Check(context.Background(), "github.com/foo/bar", "v1.0.0"); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestOSVProviderSendsGoEcosystemAndStrippedVersion(t *testing.T) {
	var gotBody map[string]any
	p := fakeOSVServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = decodeJSON(r, &gotBody)
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := p.Check(context.Background(), "github.com/foo/bar", "v1.2.3"); err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	pkg := gotBody["package"].(map[string]any)
	if pkg["ecosystem"] != "Go" {
		t.Errorf("ecosystem = %v, want Go", pkg["ecosystem"])
	}
	if pkg["name"] != "github.com/foo/bar" {
		t.Errorf("name = %v", pkg["name"])
	}
	if gotBody["version"] != "1.2.3" {
		t.Errorf("version = %v, want stripped '1.2.3'", gotBody["version"])
	}
}
