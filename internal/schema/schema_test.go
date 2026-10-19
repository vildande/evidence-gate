package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func readSample(t *testing.T, dir, file string) []byte {
	t.Helper()
	// Tests run with the package directory as the working directory.
	data, err := os.ReadFile(filepath.Join("..", "..", "samples", dir, file))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestValidSamplesHaveNoIssues(t *testing.T) {
	v := newValidator(t)
	for _, dir := range []string{"pass", "fail"} {
		for _, file := range v.Files() {
			issues, err := v.Validate(file, readSample(t, dir, file))
			if err != nil {
				t.Fatalf("%s/%s: %v", dir, file, err)
			}
			if len(issues) > 0 {
				t.Errorf("%s/%s: expected valid, got %v", dir, file, issues)
			}
		}
	}
}

func TestInvalidSamplesReportEachProblem(t *testing.T) {
	v := newValidator(t)

	// Each entry is a JSON pointer we expect to see flagged. Checking paths
	// rather than exact messages keeps the test stable across library versions.
	tests := []struct {
		file      string
		wantPaths []string
	}{
		{"test-report.json", []string{
			"",                  // missing "commit"
			"/kind",             // wrong const
			"/generated_at",     // not RFC 3339
			"/summary/failed",   // negative count
			"/coverage_percent", // above 100
		}},
		{"vuln-scan.json", []string{
			"/findings/0",          // unknown "score" property
			"/findings/0/severity", // not in the enum
		}},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			issues, err := v.Validate(tt.file, readSample(t, "invalid", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]bool)
			for _, is := range issues {
				got[is.Path] = true
			}
			for _, p := range tt.wantPaths {
				if !got[p] {
					t.Errorf("no issue reported at %q; got %v", p, issues)
				}
			}
		})
	}
}

func TestMissingCommitIsNamed(t *testing.T) {
	v := newValidator(t)
	issues, _ := v.Validate("test-report.json", readSample(t, "invalid", "test-report.json"))
	for _, is := range issues {
		if is.Path == "" && strings.Contains(is.Message, "commit") {
			return
		}
	}
	t.Errorf("expected an issue mentioning the missing 'commit' field, got %v", issues)
}

func TestMalformedJSONIsAnIssue(t *testing.T) {
	v := newValidator(t)
	issues, err := v.Validate("test-report.json", []byte(`{"kind": "test-report",`))
	if err != nil {
		t.Fatalf("malformed JSON should be an issue, not an error: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "not valid JSON") {
		t.Errorf("got %v", issues)
	}
}

func TestUnknownFileIsAnError(t *testing.T) {
	v := newValidator(t)
	if _, err := v.Validate("random.json", []byte(`{}`)); err == nil {
		t.Error("expected an error for a file with no schema")
	}
}
