package module

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseGoListOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []GoListModule
		// wantSkipped is the number of skip records a malformed record
		// produces; the parser records the problem instead of failing.
		wantSkipped int
	}{
		{
			name: "single module with update",
			input: `{"path":"github.com/foo/bar","version":"v1.0.0","indirect":false,"main":false,"update":{"path":"github.com/foo/bar","version":"v1.2.0"}}
`,
			want: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/bar", Version: "v1.2.0"},
				},
			},
		},
		{
			name: "multiple modules",
			input: `{"path":"github.com/foo/bar","version":"v1.0.0","indirect":false,"main":false,"update":{"path":"github.com/foo/bar","version":"v1.2.0"}}
{"path":"github.com/foo/baz","version":"v2.0.0","indirect":true,"main":false}
{"path":"example.com/main","version":"v0.0.0","indirect":false,"main":true}
`,
			want: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/bar", Version: "v1.2.0"},
				},
				{
					Path:     "github.com/foo/baz",
					Version:  "v2.0.0",
					Indirect: true,
					Main:     false,
					Update:   nil,
				},
				{
					Path:     "example.com/main",
					Version:  "v0.0.0",
					Indirect: false,
					Main:     true,
					Update:   nil,
				},
			},
		},
		{
			name: "module with no update field",
			input: `{"path":"github.com/foo/bar","version":"v1.0.0","indirect":false,"main":false}
`,
			want: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update:   nil,
				},
			},
		},
		{
			name:        "empty input",
			input:       ``,
			want:        nil,
			wantSkipped: 0,
		},
		{
			// A malformed record must not abort the parse: earlier modules
			// survive and the damage is reported as a skip.
			name: "malformed record after a good one",
			input: `{"path":"github.com/foo/bar","version":"v1.0.0"}
{not json`,
			want: []GoListModule{
				{Path: "github.com/foo/bar", Version: "v1.0.0"},
			},
			wantSkipped: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, skipped := parseGoListOutput([]byte(tt.input))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseGoListOutput() = %+v, want %+v", got, tt.want)
			}
			if len(skipped) != tt.wantSkipped {
				t.Errorf("parseGoListOutput() skipped %d records, want %d: %+v",
					len(skipped), tt.wantSkipped, skipped)
			}
		})
	}
}

func TestConvertToDependencies(t *testing.T) {
	tests := []struct {
		name            string
		modules         []GoListModule
		includeIndirect bool
		want            []Dependency
		wantSkipped     []SkippedDependency
	}{
		{
			name: "direct only, exclude indirect",
			modules: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/bar", Version: "v2.0.0"},
				},
				{
					Path:     "github.com/foo/baz",
					Version:  "v1.0.0",
					Indirect: true,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/baz", Version: "v2.0.0"},
				},
			},
			includeIndirect: false,
			want: []Dependency{
				{
					Path:           "github.com/foo/bar",
					CurrentVersion: "v1.0.0",
					LatestVersion:  "v2.0.0",
					Indirect:       false,
					UpdateType:     UpdateMajor,
				},
			},
		},
		{
			name: "include indirect",
			modules: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/bar", Version: "v2.0.0"},
				},
				{
					Path:     "github.com/foo/baz",
					Version:  "v1.0.0",
					Indirect: true,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/baz", Version: "v1.1.0"},
				},
			},
			includeIndirect: true,
			want: []Dependency{
				{
					Path:           "github.com/foo/bar",
					CurrentVersion: "v1.0.0",
					LatestVersion:  "v2.0.0",
					Indirect:       false,
					UpdateType:     UpdateMajor,
				},
				{
					Path:           "github.com/foo/baz",
					CurrentVersion: "v1.0.0",
					LatestVersion:  "v1.1.0",
					Indirect:       true,
					UpdateType:     UpdateMinor,
				},
			},
		},
		{
			name: "skip main module",
			modules: []GoListModule{
				{
					Path:     "example.com/main",
					Version:  "v0.0.0",
					Indirect: false,
					Main:     true,
					Update:   nil,
				},
			},
			includeIndirect: false,
			want:            nil,
		},
		{
			name: "skip modules without updates",
			modules: []GoListModule{
				{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update:   nil,
				},
			},
			includeIndirect: false,
			want:            nil,
		},
		{
			// A module go could not load (reported because of -e) becomes a
			// skip record carrying go's own message, while healthy modules
			// are still converted.
			name: "load error becomes a skip",
			modules: []GoListModule{
				{
					Path:     "github.com/foo/broken",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Error: &struct {
						Err string `json:"Err"`
					}{Err: "cannot find module providing package"},
				},
				{
					Path:     "github.com/foo/ok",
					Version:  "v1.0.0",
					Indirect: false,
					Main:     false,
					Update: &struct {
						Path    string `json:"path"`
						Version string `json:"version"`
					}{Path: "github.com/foo/ok", Version: "v1.1.0"},
				},
			},
			includeIndirect: false,
			want: []Dependency{
				{
					Path:           "github.com/foo/ok",
					CurrentVersion: "v1.0.0",
					LatestVersion:  "v1.1.0",
					Indirect:       false,
					UpdateType:     UpdateMinor,
				},
			},
			wantSkipped: []SkippedDependency{
				{Path: "github.com/foo/broken", Reason: errors.New("cannot find module providing package")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, skipped := convertToDependencies(tt.modules, tt.includeIndirect)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToDependencies() = %+v, want %+v", got, tt.want)
			}
			if len(skipped) != len(tt.wantSkipped) {
				t.Fatalf("skipped = %+v, want %+v", skipped, tt.wantSkipped)
			}
			for i, want := range tt.wantSkipped {
				if skipped[i].Path != want.Path {
					t.Errorf("skipped[%d].Path = %q, want %q", i, skipped[i].Path, want.Path)
				}
				if skipped[i].Reason == nil || skipped[i].Reason.Error() != want.Reason.Error() {
					t.Errorf("skipped[%d].Reason = %v, want %v", i, skipped[i].Reason, want.Reason)
				}
			}
		})
	}
}
