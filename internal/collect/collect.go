// Package collect turns the raw output of `go test -json -coverprofile` into a
// test report in the evidence format (schemas/test-report.schema.json).
// it only records what happened; deciding pass or fail is the job of the policies.
package collect

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Summary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// field order matches the schema, so the written file reads like the docs
type Report struct {
	Kind            string   `json:"kind"`
	Project         string   `json:"project"`
	Commit          string   `json:"commit"`
	GeneratedAt     string   `json:"generated_at"`
	Summary         Summary  `json:"summary"`
	CoveragePercent float64  `json:"coverage_percent"`
	FailedTests     []string `json:"failed_tests"`
	SkippedTests    []string `json:"skipped_tests"`
}

// build the report. commit is the commit that was tested, now the time of collection
func Build(testJSON, coverProfile io.Reader, project, commit string, now time.Time) (Report, error) {
	if project == "" || commit == "" {
		return Report{}, errors.New("project and commit are required")
	}

	tests, err := ParseTests(testJSON)
	if err != nil {
		return Report{}, fmt.Errorf("test json: %w", err)
	}
	coverage, err := Coverage(coverProfile)
	if err != nil {
		return Report{}, fmt.Errorf("coverage profile: %w", err)
	}

	return Report{
		Kind:            "test-report",
		Project:         project,
		Commit:          commit,
		GeneratedAt:     now.UTC().Format(time.RFC3339),
		Summary:         tests.Summary,
		CoveragePercent: coverage,
		FailedTests:     tests.Failed,
		SkippedTests:    tests.Skipped,
	}, nil
}

// counts and names of tests, names are "<package>.<test>", e.g. "pricing.TestCalculate/fixed_discount"
type Tests struct {
	Summary Summary
	Failed  []string // sorted
	Skipped []string // sorted
}

// one line of `go test -json`, see `go doc test2json`
type event struct {
	Action      string
	Package     string
	Test        string
	FailedBuild string // set on a package "fail" when the package did not compile
}

// read `go test -json` output.
//
// subtests: a parent test passes or fails with its subtests, so counting both
// would count one failure twice. only leaf tests are counted, except a parent that
// failed on its own (no failed subtest), which would otherwise be lost.
//
// a package that failed without any failed test (does not compile, panics in
// TestMain, ...) is counted as one failed entry, so a broken build cannot pass.
func ParseTests(r io.Reader) (Tests, error) {
	results := make(map[string]map[string]string) // package -> test -> pass/fail/skip
	pkgFailed := make(map[string]string)          // package -> why the package failed
	events := 0

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // test output lines can be long
	for line := 1; sc.Scan(); line++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return Tests{}, fmt.Errorf("line %d: not a go test -json event: %w", line, err)
		}
		events++

		if e.Package == "" {
			continue // build-output / build-fail events; the package "fail" event follows
		}
		if e.Action != "pass" && e.Action != "fail" && e.Action != "skip" {
			continue // run, output, pause, ...
		}

		if e.Test == "" { // package result
			if e.Action == "fail" {
				pkgFailed[e.Package] = "package failed"
				if e.FailedBuild != "" {
					pkgFailed[e.Package] = "build failed"
				}
			}
			continue // a package "skip" means it has no test files
		}

		if results[e.Package] == nil {
			results[e.Package] = make(map[string]string)
		}
		results[e.Package][e.Test] = e.Action
	}
	if err := sc.Err(); err != nil {
		return Tests{}, err
	}
	if events == 0 {
		return Tests{}, errors.New("no events: did go test run with -json?")
	}

	var t Tests
	for _, pkg := range slices.Sorted(maps.Keys(results)) {
		tests := results[pkg]
		for _, name := range slices.Sorted(maps.Keys(tests)) {
			action := tests[name]
			if hasSubtests(tests, name) && (action != "fail" || subtestFailed(tests, name)) {
				continue
			}
			full := path.Base(pkg) + "." + name
			switch action {
			case "pass":
				t.Summary.Passed++
			case "fail":
				t.Summary.Failed++
				t.Failed = append(t.Failed, full)
			case "skip":
				t.Summary.Skipped++
				t.Skipped = append(t.Skipped, full)
			}
		}
	}

	for _, pkg := range slices.Sorted(maps.Keys(pkgFailed)) {
		if packageHasFailedTest(results[pkg]) {
			continue // the failed tests already explain it
		}
		t.Summary.Failed++
		t.Failed = append(t.Failed, fmt.Sprintf("%s [%s]", path.Base(pkg), pkgFailed[pkg]))
	}

	t.Summary.Total = t.Summary.Passed + t.Summary.Failed + t.Summary.Skipped
	slices.Sort(t.Failed) // package entries were appended last
	t.Failed = orEmpty(t.Failed)
	t.Skipped = orEmpty(t.Skipped)
	return t, nil
}

func hasSubtests(tests map[string]string, name string) bool {
	for other := range tests {
		if strings.HasPrefix(other, name+"/") {
			return true
		}
	}
	return false
}

func subtestFailed(tests map[string]string, name string) bool {
	for other, action := range tests {
		if strings.HasPrefix(other, name+"/") && action == "fail" {
			return true
		}
	}
	return false
}

func packageHasFailedTest(tests map[string]string) bool {
	for _, action := range tests {
		if action == "fail" {
			return true
		}
	}
	return false
}

// empty lists, not null: the schema requires arrays
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// statement coverage in percent, one decimal, from a -coverprofile file.
//
// line format: "file.go:12.5,14.2 3 1" = block, number of statements, times run.
// the same block can appear more than once (several packages in one profile);
// it counts once and is covered if any line ran it
func Coverage(r io.Reader) (float64, error) {
	type block struct {
		statements int
		covered    bool
	}
	blocks := make(map[string]block)

	sc := bufio.NewScanner(r)
	sawMode := false
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "mode: ") {
			sawMode = true
			continue
		}
		if !sawMode {
			return 0, fmt.Errorf("line %d: expected a \"mode:\" line first", line)
		}

		fields := strings.Fields(text)
		if len(fields) != 3 {
			return 0, fmt.Errorf("line %d: want \"block statements count\", got %q", line, text)
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("line %d: %w", line, err)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, fmt.Errorf("line %d: %w", line, err)
		}

		b := blocks[fields[0]]
		b.statements = statements
		b.covered = b.covered || count > 0
		blocks[fields[0]] = b
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if !sawMode {
		return 0, errors.New("empty profile: did go test run with -coverprofile?")
	}

	total, covered := 0, 0
	for _, b := range blocks {
		total += b.statements
		if b.covered {
			covered += b.statements
		}
	}
	if total == 0 {
		return 0, nil // nothing compiled, e.g. a build failure
	}
	return math.Round(float64(covered)*1000/float64(total)) / 10, nil
}
