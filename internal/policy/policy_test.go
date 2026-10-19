package policy

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"
)

// Tests:
// TestRegoUnitTests — runs policies/gate_test.rego through the OPA SDK, same as `opa test policies/`.
// TestLoadDirSkipsTestFiles — checks that *_test.rego files are not loaded as policies.
// TestLoadDirWithoutPoliciesIsAnError — checks that an empty policy directory is an error, not a silent PASS.
// TestPassSampleHasNoViolations — checks that samples/pass passes all rules.
// TestFailSampleViolations — checks that samples/fail fails TEST-002 and VULN-001 with fix hints.
// TestExpiredExceptionBlocks — checks that the pass sample fails VULN-002 once its exception has expired.
// TestCompileErrorNamesTheFile — checks that a broken module fails to compile with its file name in the error.
// TestMissingDenyIsAnError — checks that policies without deny rules are an error, not a silent PASS.
// TestBadDenyShapeIsAnError — checks that a deny entry that is not an object is rejected.

const today = "2026-10-19"

var policiesDir = filepath.Join("..", "..", "policies")

func sampleDir(name string) string {
	return filepath.Join("..", "..", "samples", name)
}

// load and compile the bundled policies
func newEngine(t *testing.T) *Engine {
	t.Helper()
	modules, err := LoadDir(policiesDir)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Compile(context.Background(), modules)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// evaluate the bundled policies on a sample directory
func evalSample(t *testing.T, dir, now string) []Violation {
	t.Helper()
	in, err := ReadInput(sampleDir(dir), now)
	if err != nil {
		t.Fatal(err)
	}
	violations, err := newEngine(t).Eval(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return violations
}

// compile modules that are expected to compile, then evaluate an empty input
func evalModules(t *testing.T, modules map[string]string) ([]Violation, error) {
	t.Helper()
	e, err := Compile(context.Background(), modules)
	if err != nil {
		t.Fatal(err)
	}
	return e.Eval(context.Background(), Input{Now: today})
}

func TestRegoUnitTests(t *testing.T) {
	results, err := tester.Run(context.Background(), policiesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no Rego tests found")
	}
	for _, r := range results {
		if !r.Pass() {
			t.Errorf("%s.%s: fail=%v error=%v", r.Package, r.Name, r.Fail, r.Error)
		}
	}
}

func TestLoadDirSkipsTestFiles(t *testing.T) {
	modules, err := LoadDir(policiesDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := modules["gate.rego"]; !ok || len(modules) != 1 {
		t.Errorf("want only gate.rego, got %v", slices.Sorted(maps.Keys(modules)))
	}
}

func TestLoadDirWithoutPoliciesIsAnError(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Error("expected an error for a directory with no .rego files")
	}
}

func TestPassSampleHasNoViolations(t *testing.T) {
	if v := evalSample(t, "pass", today); len(v) != 0 {
		t.Errorf("want no violations, got %v", v)
	}
}

func TestFailSampleViolations(t *testing.T) {
	got := evalSample(t, "fail", today)
	want := []Violation{
		{
			Rule:    "TEST-002",
			Message: "coverage 72% is below 80%",
			Fix:     "raise coverage from 72% to at least 80%",
		},
		{
			Rule:    "VULN-001",
			Message: "critical vulnerability CVE-2026-1234 in openssl 3.0.8",
			Fix:     "upgrade openssl to >= 3.0.12",
		},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestExpiredExceptionBlocks(t *testing.T) {
	// the pass sample's exception for CVE-2026-5678 expires on 2026-12-31
	got := evalSample(t, "pass", "2027-01-01")
	if len(got) != 1 || got[0].Rule != "VULN-002" || !strings.Contains(got[0].Message, "CVE-2026-5678") {
		t.Errorf("want one VULN-002 violation for CVE-2026-5678, got %v", got)
	}
}

func TestCompileErrorNamesTheFile(t *testing.T) {
	modules := map[string]string{
		"draft.rego": "package evidencegate\n\ndeny contains x if {\n", // unclosed brace
	}
	_, err := Compile(context.Background(), modules)
	if err == nil || !strings.Contains(err.Error(), "draft.rego") {
		t.Errorf("want a compile error naming draft.rego, got %v", err)
	}
}

func TestMissingDenyIsAnError(t *testing.T) {
	modules := map[string]string{"other.rego": "package evidencegate\n\nallow := true\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error when no deny rule exists")
	}
}

func TestBadDenyShapeIsAnError(t *testing.T) {
	modules := map[string]string{"bad.rego": "package evidencegate\n\ndeny contains \"just a string\"\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error for a deny entry that is not an object")
	}
}
