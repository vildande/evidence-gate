package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vildande/evidence-gate/internal/audit"
	"github.com/vildande/evidence-gate/internal/policy"
	"github.com/vildande/evidence-gate/internal/report"
	"github.com/vildande/evidence-gate/internal/schema"
	"github.com/vildande/evidence-gate/policies"
)

func runCheck(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("check", flag.ContinueOnError)
	fl.SetOutput(stderr)
	evidenceDir := fl.String("evidence", "", "evidence directory (required)")
	policiesDir := fl.String("policies", "", "policy directory (default: policies bundled in the binary)")
	asJSON := fl.Bool("json", false, "print the result as JSON")
	summary := fl.String("summary", "", "append a Markdown summary to this file, e.g. $GITHUB_STEP_SUMMARY")
	if err := fl.Parse(args); err != nil {
		return parseExit(err)
	}
	if *evidenceDir == "" || fl.NArg() > 0 {
		fmt.Fprint(stderr, "check: --evidence dir is required\n\n"+usage)
		return exitError
	}

	r, err := check(context.Background(), *evidenceDir, *policiesDir, time.Now().UTC())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	if *asJSON {
		err = report.WriteJSON(stdout, r)
	} else {
		err = report.WriteText(stdout, r, isTerminal(stdout))
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	if *summary != "" {
		if err := appendSummary(*summary, r); err != nil {
			fmt.Fprintln(stderr, "error: summary:", err)
			return exitError
		}
	}

	switch r.Result() {
	case report.Pass:
		return exitPass
	case report.Fail:
		return exitFail
	default:
		return exitError
	}
}

// schema -> policy -> report. policies are compiled first: a broken policy is an
// error (exit 2) whatever the evidence says
func check(ctx context.Context, evidenceDir, policiesDir string, now time.Time) (report.Report, error) {
	modules, err := loadPolicies(policiesDir)
	if err != nil {
		return report.Report{}, err
	}
	engine, err := policy.Compile(ctx, modules)
	if err != nil {
		return report.Report{}, err
	}

	v, err := schema.New()
	if err != nil {
		return report.Report{}, err
	}
	results, err := v.ValidateDir(evidenceDir)
	if err != nil {
		return report.Report{}, err
	}

	r := report.Report{
		Version:       version,
		CheckedAt:     now,
		PolicyVersion: audit.Policies(modules),
		Schema:        results,
	}

	// fingerprint every evidence file that exists, valid or not
	for _, f := range results {
		sum, err := audit.File(filepath.Join(evidenceDir, f.File))
		if errors.Is(err, fs.ErrNotExist) {
			continue // already reported as "file is missing"
		}
		if err != nil {
			return report.Report{}, err
		}
		r.Evidence = append(r.Evidence, report.Evidence{File: f.File, SHA256: sum})
	}

	// invalid evidence is never evaluated: policies could read missing fields as "fine"
	if r.Result() == report.Invalid {
		return r, nil
	}

	in, err := policy.ReadInput(evidenceDir, now.Format(time.DateOnly))
	if err != nil {
		return report.Report{}, err
	}
	r.Project = projectOf(in)
	if r.Policy, err = engine.Eval(ctx, in); err != nil {
		return report.Report{}, err
	}
	return r, nil
}

// --policies dir, or the policies embedded in the binary
func loadPolicies(dir string) (map[string]string, error) {
	if dir == "" {
		return policy.LoadFS(policies.FS)
	}
	return policy.LoadDir(dir)
}

// the schema guarantees test_report.project is a non-empty string
func projectOf(in policy.Input) string {
	tr, _ := in.TestReport.(map[string]any)
	project, _ := tr["project"].(string)
	return project
}

func appendSummary(path string, r report.Report) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := report.WriteMarkdown(f, r); err != nil {
		return errors.Join(err, f.Close()) // report both, the write error first
	}
	return f.Close() // a failed close can mean the data never reached the disk
}

// colors only when a person is watching, not in files or CI logs
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
