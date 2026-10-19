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
		results, err := v.ValidateDir(filepath.Join("..", "..", "samples", dir))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, r := range results {
			if len(r.Issues) > 0 {
				t.Errorf("%s/%s: expected valid, got %v", dir, r.File, r.Issues)
			}
		}
	}
}

func TestExceptionsAreValidatedOnlyWhenPresent(t *testing.T) {
	v := newValidator(t)
	tests := []struct {
		dir       string
		wantFiles []string
	}{
		{"pass", []string{"exceptions.json", "test-report.json", "vuln-scan.json"}},
		{"fail", []string{"test-report.json", "vuln-scan.json"}}, // has no exceptions.json
	}
	for _, tt := range tests {
		results, err := v.ValidateDir(filepath.Join("..", "..", "samples", tt.dir))
		if err != nil {
			t.Fatalf("%s: %v", tt.dir, err)
		}
		var got []string
		for _, r := range results {
			got = append(got, r.File)
		}
		if strings.Join(got, ",") != strings.Join(tt.wantFiles, ",") {
			t.Errorf("%s: validated %v, want %v", tt.dir, got, tt.wantFiles)
		}
	}
}

func TestMissingRequiredFileIsAnIssue(t *testing.T) {
	v := newValidator(t)
	dir := t.TempDir() // empty directory, removed automatically after the test
	results, err := v.ValidateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("want issues for the 2 required files, got %v", results)
	}
	for _, r := range results {
		if len(r.Issues) != 1 || r.Issues[0].Message != "file is missing" {
			t.Errorf("%s: got %v", r.File, r.Issues)
		}
	}
}

func TestExpiresMustBeACalendarDate(t *testing.T) {
	v := newValidator(t)
	tests := []struct {
		expires string
		valid   bool
	}{
		{"2026-12-31", true},
		{"2028-02-29", true},            // leap day
		{"2026-02-30", false},           // no such day
		{"2026-1-5", false},             // needs two-digit month and day
		{"31/12/2026", false},           // wrong order and separator
		{"2026-12-31T00:00:00Z", false}, // a timestamp, not a date
		{"", false},
	}
	for _, tt := range tests {
		doc := `[{"cve": "CVE-1", "reason": "r", "approved_by": "a", "expires": "` + tt.expires + `"}]`
		issues, err := v.Validate("exceptions.json", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if gotValid := len(issues) == 0; gotValid != tt.valid {
			t.Errorf("expires %q: valid=%v, want %v (issues: %v)", tt.expires, gotValid, tt.valid, issues)
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
		{"exceptions.json", []string{
			"/0/expires", // not YYYY-MM-DD
			"/1",         // missing "approved_by", unknown "ticket"
			"/1/reason",  // empty
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
	issues, err := v.Validate("test-report.json", readSample(t, "invalid", "test-report.json"))
	if err != nil {
		t.Fatal(err)
	}
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
