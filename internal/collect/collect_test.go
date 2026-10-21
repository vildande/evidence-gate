package collect

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vildande/evidence-gate/internal/schema"
)

// TestParseTestsCountsLeafTests - checks that parents with subtests are not counted twice.
// TestParseTestsFailedSubtest - checks that a failed subtest is listed, not its parent.
// TestParseTestsParentFailsOnItsOwn - checks that a parent failing without a failed subtest is listed.
// TestParseTestsSkip - checks that skipped tests are counted and listed.
// TestParseTestsBuildFailure - checks that a package that does not compile becomes a failed entry.
// TestParseTestsSameNameInTwoPackages - checks that test names include the package.
// TestParseTestsErrors - checks that empty input and non-JSON lines are errors.
// TestCoverage - checks the percentage, rounding and duplicate blocks.
// TestCoverageErrors - checks that malformed profiles are errors.
// TestBuildMatchesSchema - checks that a built report passes the test-report schema.

const pkg = "example.com/app/pricing"

// one go test -json line
func ev(action, pkg, test string) string {
	b, err := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": test})
	if err != nil {
		panic(err) // a map of strings always marshals
	}
	return string(b)
}

func parse(t *testing.T, lines ...string) Tests {
	t.Helper()
	got, err := ParseTests(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestParseTestsCountsLeafTests(t *testing.T) {
	got := parse(t,
		ev("run", pkg, "TestA"),
		ev("output", pkg, "TestA"),
		ev("pass", pkg, "TestA/x"),
		ev("pass", pkg, "TestA/y"),
		ev("pass", pkg, "TestA"),
		ev("pass", pkg, "TestB"),
		ev("pass", pkg, ""),
	)
	want := Summary{Total: 3, Passed: 3}
	if got.Summary != want || len(got.Failed) != 0 || len(got.Skipped) != 0 {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestsFailedSubtest(t *testing.T) {
	got := parse(t,
		ev("pass", pkg, "TestA/x"),
		ev("fail", pkg, "TestA/y"),
		ev("fail", pkg, "TestA"),
		ev("fail", pkg, ""),
	)
	if got.Summary != (Summary{Total: 2, Passed: 1, Failed: 1}) || !slices.Equal(got.Failed, []string{"pricing.TestA/y"}) {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestsParentFailsOnItsOwn(t *testing.T) {
	got := parse(t,
		ev("pass", pkg, "TestA/x"),
		ev("fail", pkg, "TestA"), // e.g. t.Error after the subtests
		ev("fail", pkg, ""),
	)
	if got.Summary != (Summary{Total: 2, Passed: 1, Failed: 1}) || !slices.Equal(got.Failed, []string{"pricing.TestA"}) {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestsSkip(t *testing.T) {
	got := parse(t,
		ev("skip", pkg, "TestB"),
		ev("pass", pkg, "TestA"),
		ev("skip", "example.com/app/empty", ""), // package with no test files
		ev("pass", pkg, ""),
	)
	if got.Summary != (Summary{Total: 2, Passed: 1, Skipped: 1}) || !slices.Equal(got.Skipped, []string{"pricing.TestB"}) {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestsBuildFailure(t *testing.T) {
	// real output when pricing does not compile
	got := parse(t,
		`{"ImportPath":"example.com/app/pricing","Action":"build-fail"}`,
		`{"Action":"start","Package":"example.com/app"}`,
		`{"Action":"fail","Package":"example.com/app","Elapsed":0,"FailedBuild":"example.com/app/pricing"}`,
		`{"Action":"fail","Package":"example.com/app/pricing","Elapsed":0,"FailedBuild":"example.com/app/pricing"}`,
	)
	want := []string{"app [build failed]", "pricing [build failed]"}
	if got.Summary != (Summary{Total: 2, Failed: 2}) || !slices.Equal(got.Failed, want) {
		t.Errorf("got %+v", got)
	}

	// a package can also fail with no test failing, e.g. os.Exit in TestMain
	got = parse(t, ev("pass", pkg, "TestA"), ev("fail", pkg, ""))
	if !slices.Equal(got.Failed, []string{"pricing [package failed]"}) {
		t.Errorf("got %+v", got)
	}
}

func TestParseTestsSameNameInTwoPackages(t *testing.T) {
	got := parse(t,
		ev("fail", "example.com/app/a", "TestX"),
		ev("fail", "example.com/app/b", "TestX"),
	)
	if !slices.Equal(got.Failed, []string{"a.TestX", "b.TestX"}) {
		t.Errorf("got %v", got.Failed)
	}
}

func TestParseTestsErrors(t *testing.T) {
	for _, input := range []string{
		"",
		"\n\n",
		ev("pass", pkg, "TestA") + "\nok  example.com/app 0.1s", // plain go test output mixed in
	} {
		if _, err := ParseTests(strings.NewReader(input)); err == nil {
			t.Errorf("%q: expected an error", input)
		}
	}
}

func TestCoverage(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		want    float64
	}{
		{"all covered", "mode: set\na.go:1.1,2.1 4 1\n", 100},
		{"rounds to one decimal", "mode: set\na.go:1.1,2.1 2 1\na.go:3.1,4.1 1 0\n", 66.7},
		{"counts statements, not blocks", "mode: count\na.go:1.1,2.1 9 3\na.go:3.1,4.1 1 0\n", 90},
		{"duplicate block covered once", "mode: set\na.go:1.1,2.1 1 0\nmode: set\na.go:1.1,2.1 1 1\na.go:3.1,4.1 1 0\n", 50},
		{"build failure: no blocks", "mode: set\n", 0},
	}
	for _, tt := range tests {
		got, err := Coverage(strings.NewReader(tt.profile))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCoverageErrors(t *testing.T) {
	for _, profile := range []string{
		"",
		"a.go:1.1,2.1 1 1\n",          // no mode line
		"mode: set\na.go:1.1,2.1 1\n", // missing count
		"mode: set\na.go:1.1,2.1 x 1\n",
	} {
		if _, err := Coverage(strings.NewReader(profile)); err == nil {
			t.Errorf("%q: expected an error", profile)
		}
	}
}

func TestBuildMatchesSchema(t *testing.T) {
	testJSON := strings.Join([]string{ev("pass", pkg, "TestA"), ev("skip", pkg, "TestB"), ev("pass", pkg, "")}, "\n")
	r, err := Build(strings.NewReader(testJSON), strings.NewReader("mode: set\na.go:1.1,2.1 1 1\n"),
		"demo-app", "3f9c2a1", time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if r.GeneratedAt != "2026-10-20T12:00:00Z" || r.CoveragePercent != 100 || r.Summary.Total != 2 {
		t.Errorf("got %+v", r)
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	v, err := schema.New()
	if err != nil {
		t.Fatal(err)
	}
	issues, err := v.Validate("test-report.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) > 0 {
		t.Errorf("collected report does not match the schema: %v\n%s", issues, data)
	}

	if _, err := Build(strings.NewReader(testJSON), strings.NewReader("mode: set\n"), "demo-app", "", time.Now()); err == nil {
		t.Error("expected an error for an empty commit")
	}
}
