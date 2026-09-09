package module

import (
	"reflect"
	"testing"
)

func TestParseGoListOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []GoListModule
		wantErr bool
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
			name:    "empty input",
			input:   ``,
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGoListOutput([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGoListOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseGoListOutput() = %+v, want %+v", got, tt.want)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToDependencies(tt.modules, tt.includeIndirect)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertToDependencies() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
