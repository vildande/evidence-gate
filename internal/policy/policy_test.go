package policy

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/vildande/evidence-gate/policies"
)

const today = "2026-10-19"
var policiesDir = filepath.Join("..", "..", "policies")

// dir for sample with jsons
func sampleDir(name string) string { // for example, "../../samples/pass" or "../../samples/fail"
	return filepath.Join("..", "..", "samples", name)
}

// load and compile the policies
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

// evaluate the sample directory, using the policies
func evalSample(t *testing.T, dir, now string) Result {
	t.Helper()
	in, err := ReadInput(sampleDir(dir), now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := newEngine(t).Eval(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// evaluate the modules with minimal input (just the now date)
func evalModules(t *testing.T, modules map[string]string) (Result, error) {
	t.Helper()
	e, err := Compile(context.Background(), modules)
	if err != nil {
		t.Fatal(err)
	}
	return e.Eval(context.Background(), Input{Now: today})
}

// TestRegoUnitTests - runs policies/gate_test.rego through the OPA SDK, same as `opa test policies/`.
// TestLoadDirSkipsTestFiles - checks that *_test.rego files are not loaded as policies.
// TestLoadDirWithoutPoliciesIsAnError - checks that an empty policy directory is an error, not a silent PASS.
// TestPassSampleIsWaived - checks that samples/pass passes, with its TEST-003 violation listed as waived.
// TestFailSampleViolations - checks that samples/fail fails TEST-001, TEST-002 and TEST-003 with fix hints.
// TestExpiredWaiverBlocks - checks that the pass sample fails TEST-003 once its waiver has expired.
// TestCompileErrorNamesTheFile - checks that a broken module fails to compile with its file name in the error.
// TestMissingDenyIsAnError - checks that policies without deny rules are an error, not a silent PASS.
// TestMissingWaivedIsAnError - checks that policies without a waived set are an error.
// TestMissingRulesIsAnError - checks that policies without a rules list are an error.
// TestBundledPoliciesMatchDir - checks that the policies embedded in the binary are the ones in policies/.
// TestBadDenyShapeIsAnError - checks that a deny entry that is not an object is rejected.

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

func TestPassSampleIsWaived(t *testing.T) {
	res := evalSample(t, "pass", today)
	if len(res.Deny) != 0 {
		t.Errorf("want no deny, got %v", res.Deny)
	}
	want := []Waived{{
		Rule:       "TEST-003",
		Message:    "1 skipped test(s)",
		ApprovedBy: "qa-lead",
		Reason:     "Rates API sandbox is down, tracked in #12",
		Expires:    "2099-12-31",
	}}
	if !slices.Equal(res.Waived, want) {
		t.Errorf("waived\ngot  %v\nwant %v", res.Waived, want)
	}
	if res.Rules["TEST-002"] != "coverage 88.2% (>= 80%)" {
		t.Errorf("rules: got %v", res.Rules)
	}
}

func TestFailSampleViolations(t *testing.T) {
	res := evalSample(t, "fail", today)
	want := []Violation{
		{
			Rule:    "TEST-001",
			Message: "1 failed test(s)",
			Fix:     "fix failing tests: TestCalculate/fixed_discount",
		},
		{
			Rule:    "TEST-002",
			Message: "coverage 72% (< 80%)",
			Fix:     "raise coverage from 72% to at least 80%",
		},
		{
			Rule:    "TEST-003",
			Message: "1 skipped test(s)",
			Fix:     "un-skip tests: TestQuoteLiveRates",
		},
	}
	if !slices.Equal(res.Deny, want) {
		t.Errorf("got  %v\nwant %v", res.Deny, want)
	}
	if len(res.Waived) != 0 { // the fail sample has no waivers.json
		t.Errorf("want nothing waived, got %v", res.Waived)
	}
}

func TestExpiredWaiverBlocks(t *testing.T) {
	// the pass sample's TEST-003 waiver expires on 2099-12-31
	res := evalSample(t, "pass", "2100-01-01")
	if len(res.Deny) != 1 || res.Deny[0].Rule != "TEST-003" {
		t.Errorf("want one TEST-003 violation, got %v", res.Deny)
	}
	if len(res.Waived) != 0 {
		t.Errorf("want nothing waived, got %v", res.Waived)
	}
}

func TestCompileErrorNamesTheFile(t *testing.T) {
	modules := map[string]string{
		"broken.rego": "package evidencegate\n\ndeny contains x if {\n", // unclosed brace
	}
	_, err := Compile(context.Background(), modules)
	if err == nil || !strings.Contains(err.Error(), "broken.rego") {
		t.Errorf("want a compile error naming broken.rego, got %v", err)
	}
}

func TestMissingDenyIsAnError(t *testing.T) {
	modules := map[string]string{"other.rego": "package evidencegate\n\nwaived := set()\n\nrules := {}\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error when no deny rule exists")
	}
}

func TestMissingWaivedIsAnError(t *testing.T) {
	modules := map[string]string{"other.rego": "package evidencegate\n\ndeny := set()\n\nrules := {}\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error when no waived rule exists")
	}
}

func TestBadDenyShapeIsAnError(t *testing.T) {
	modules := map[string]string{"bad.rego": "package evidencegate\n\ndeny contains \"just a string\"\n\nwaived := set()\n\nrules := {}\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error for a deny entry that is not an object")
	}
}

func TestMissingRulesIsAnError(t *testing.T) {
	modules := map[string]string{"other.rego": "package evidencegate\n\ndeny := set()\n\nwaived := set()\n"}
	if _, err := evalModules(t, modules); err == nil {
		t.Error("expected an error when no rules list exists")
	}
}

func TestBundledPoliciesMatchDir(t *testing.T) {
	bundled, err := LoadFS(policies.FS)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := LoadDir(policiesDir)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(bundled, onDisk) {
		t.Errorf("bundled %v, on disk %v", slices.Sorted(maps.Keys(bundled)), slices.Sorted(maps.Keys(onDisk)))
	}
}
