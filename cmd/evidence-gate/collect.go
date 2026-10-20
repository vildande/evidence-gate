package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vildande/evidence-gate/internal/collect"
)

// exits 0 even when tests failed: collect only records, check decides
func runCollect(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("collect", flag.ContinueOnError)
	fl.SetOutput(stderr)
	testJSON := fl.String("test-json", "", "output of go test -json (required)")
	coverage := fl.String("coverage", "", "profile from go test -coverprofile (required)")
	project := fl.String("project", "", "project name (required)")
	commit := fl.String("commit", "", "commit that was tested (required)")
	out := fl.String("out", "", "where to write test-report.json (required)")
	if err := fl.Parse(args); err != nil {
		return parseExit(err)
	}
	if *testJSON == "" || *coverage == "" || *project == "" || *commit == "" || *out == "" || fl.NArg() > 0 {
		fmt.Fprint(stderr, "collect: --test-json, --coverage, --project, --commit and --out are required\n\n"+usage)
		return exitError
	}

	r, err := collectReport(*testJSON, *coverage, *project, *commit, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if err := writeReport(*out, r); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	s := r.Summary
	fmt.Fprintf(stdout, "✓ collect %s @ %s: %d tests (%d passed, %d failed, %d skipped), coverage %v%% → %s\n",
		r.Project, r.Commit, s.Total, s.Passed, s.Failed, s.Skipped, r.CoveragePercent, *out)
	return exitPass
}

// both files are read whole: they are small, and there is no file to close
func collectReport(testJSONPath, coveragePath, project, commit string, now time.Time) (collect.Report, error) {
	testJSON, err := os.ReadFile(testJSONPath)
	if err != nil {
		return collect.Report{}, err
	}
	profile, err := os.ReadFile(coveragePath)
	if err != nil {
		return collect.Report{}, err
	}
	return collect.Build(bytes.NewReader(testJSON), bytes.NewReader(profile), project, commit, now)
}

// write the report as indented JSON, creating the evidence directory if needed
func writeReport(path string, r collect.Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
