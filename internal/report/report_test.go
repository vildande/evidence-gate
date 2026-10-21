package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vildande/evidence-gate/internal/policy"
	"github.com/vildande/evidence-gate/internal/schema"
)

// TestTextFail — checks the full text output of a failing check, as in the spec.
// TestTextWaivedPass — checks that a waived rule is shown with ⚠ and the result counts it.
// TestTextInvalid — checks that schema issues are listed and policies are not shown.
// TestTextColorOnlyWhenAsked — checks that ANSI colors appear only with color=true.
// TestJSON — checks the JSON fields, including empty lists instead of null.
// TestJSONInvalidListsSchemaErrors — checks that schema errors are in the JSON for INVALID.
// TestMarkdown — checks the summary table rows and escaping.

var rules = map[string]string{
	"TEST-001": "no failed tests",
	"TEST-002": "coverage 86.1% (≥ 80%)",
	"TEST-003": "no skipped tests",
}

var validSchema = []schema.FileResult{{File: "test-report.json"}, {File: "waivers.json"}}

var evidence = []Evidence{
	{File: "test-report.json", SHA256: "9a1f000000000000000000000000000000000000000000000000000000000c3"},
	{File: "waivers.json", SHA256: "4be00000000000000000000000000000000000000000000000000000000007d"},
}

func failReport() Report {
	return Report{
		Version:   "v1.0.0",
		Project:   "demo-app",
		CheckedAt: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		Schema:    validSchema,
		Policy: policy.Result{
			Deny:  []policy.Violation{{Rule: "TEST-001", Message: "1 failed test(s)", Fix: "fix failing tests: TestQuoteDiscount"}},
			Rules: rules,
		},
		Evidence: evidence,
	}
}

func waivedReport() Report {
	r := failReport()
	r.Policy = policy.Result{
		Waived: []policy.Waived{{
			Rule: "TEST-002", Message: "coverage 75% (< 80%)",
			ApprovedBy: "qa-lead", Reason: "new HTTP client, tests in #14", Expires: "2026-10-27",
		}},
		Rules: rules,
	}
	return r
}

func text(t *testing.T, r Report, color bool) string {
	t.Helper()
	var sb strings.Builder
	if err := WriteText(&sb, r, color); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func TestTextFail(t *testing.T) {
	want := `evidence-gate v1.0.0 | demo-app

✓ schema   test-report.json
✓ schema   waivers.json
✗ TEST-001 1 failed test(s)
           fix: fix failing tests: TestQuoteDiscount
✓ TEST-002 coverage 86.1% (≥ 80%)
✓ TEST-003 no skipped tests

RESULT: FAIL (1 of 3 rules failed)
evidence sha256: test-report 9a1f…c3 | waivers 4be0…7d
`
	if got := text(t, failReport(), false); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTextWaivedPass(t *testing.T) {
	r := waivedReport()
	if r.Result() != Pass {
		t.Fatalf("result %s, want PASS", r.Result())
	}
	got := text(t, r, false)
	for _, line := range []string{
		"⚠ TEST-002 coverage 75% (< 80%) — waived by qa-lead until 2026-10-27: new HTTP client, tests in #14\n",
		"✓ TEST-001 no failed tests\n",
		"RESULT: PASS (1 rule waived)\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	if strings.Contains(got, "✓ TEST-002") {
		t.Errorf("waived rule shown as a pass:\n%s", got)
	}
}

func TestTextInvalid(t *testing.T) {
	r := failReport()
	r.Project = ""
	r.Schema = []schema.FileResult{
		{File: "test-report.json", Issues: []schema.Issue{{Path: "/coverage_percent", Message: "must be <= 100"}}},
	}
	r.Policy = policy.Result{}
	r.Evidence = r.Evidence[:1]

	want := `evidence-gate v1.0.0

✗ schema   test-report.json
           /coverage_percent: must be <= 100

RESULT: INVALID (evidence does not match the schema)
evidence sha256: test-report 9a1f…c3
`
	if got := text(t, r, false); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTextColorOnlyWhenAsked(t *testing.T) {
	if strings.Contains(text(t, failReport(), false), "\033[") {
		t.Error("colors without color=true")
	}
	if !strings.Contains(text(t, failReport(), true), red+"✗"+reset) {
		t.Error("no red ✗ with color=true")
	}
}

func decodeJSON(t *testing.T, r Report) map[string]any {
	t.Helper()
	var sb strings.Builder
	if err := WriteJSON(&sb, r); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(sb.String()), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, sb.String())
	}
	return got
}

func TestJSON(t *testing.T) {
	r := waivedReport()
	r.PolicyVersion = "abc"
	got := decodeJSON(t, r)

	if got["result"] != "PASS" || got["project"] != "demo-app" || got["policy_version"] != "abc" {
		t.Errorf("got %v", got)
	}
	if got["checked_at"] != "2026-10-20T12:00:00Z" {
		t.Errorf("checked_at %v", got["checked_at"])
	}
	if v, ok := got["violations"].([]any); !ok || len(v) != 0 {
		t.Errorf("violations should be an empty list, got %v", got["violations"])
	}
	waived, ok := got["waived"].([]any)
	if !ok || len(waived) != 1 || waived[0].(map[string]any)["approved_by"] != "qa-lead" {
		t.Errorf("waived %v", got["waived"])
	}
	if len(got["evidence"].([]any)) != 2 {
		t.Errorf("evidence %v", got["evidence"])
	}
	if _, ok := got["schema_errors"]; ok {
		t.Error("schema_errors should be left out when evidence is valid")
	}
}

func TestJSONInvalidListsSchemaErrors(t *testing.T) {
	r := failReport()
	r.Schema = []schema.FileResult{{File: "waivers.json", Issues: []schema.Issue{{Path: "/0/rule", Message: "bad"}}}}
	got := decodeJSON(t, r)
	if got["result"] != "INVALID" {
		t.Errorf("result %v", got["result"])
	}
	errs, ok := got["schema_errors"].([]any)
	if !ok || len(errs) != 1 || errs[0].(map[string]any)["path"] != "/0/rule" {
		t.Errorf("schema_errors %v", got["schema_errors"])
	}
}

func TestMarkdown(t *testing.T) {
	r := waivedReport()
	r.Policy.Deny = []policy.Violation{{Rule: "TEST-001", Message: "a | b", Fix: "do x"}}

	var sb strings.Builder
	if err := WriteMarkdown(&sb, r); err != nil {
		t.Fatal(err)
	}
	got := sb.String()
	for _, line := range []string{
		"### evidence-gate v1.0.0 | demo-app\n",
		"| ✓ | schema | test-report.json |\n",
		"| ✗ | TEST-001 | a \\| b<br>fix: do x |\n",
		"| ⚠ | TEST-002 | coverage 75% (&lt; 80%) — waived by qa-lead until 2026-10-27: new HTTP client, tests in #14 |\n",
		"| ✓ | TEST-003 | no skipped tests |\n",
		"**RESULT: FAIL (1 of 3 rules failed, 1 rule waived)**\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}
