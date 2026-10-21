package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckExitCodes - checks exit codes 0/1/2 on the pass, fail and invalid samples, and on a missing dir.
// TestCheckPassShowsWaiver - checks that samples/pass passes with its TEST-003 waiver visible.
// TestCheckFailShowsFixes - checks that samples/fail lists every failed rule with a fix hint.
// TestCheckJSON - checks that --json prints valid JSON with the result and evidence hashes.
// TestCheckSummaryAppends - checks that --summary appends Markdown instead of overwriting the file.
// TestCheckPoliciesDir - checks that --policies loads policies from a directory.
// TestCheckBrokenPolicyIsAnError - checks that a policy that does not compile exits 2.
// TestCollectThenCheck - checks the full flow: collect writes a report that check accepts (pass, fail, build failure).
// TestCollectErrors - checks that missing flags and unreadable inputs exit 2.
// TestUsageErrors - checks exit codes for no command, unknown command, missing --evidence and -h.
// TestVersion - checks that version prints the version.

func sample(name string) string {
	return filepath.Join("..", "..", "samples", name)
}

// call run like the shell would, return exit code, stdout and stderr
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCheckExitCodes(t *testing.T) {
	tests := []struct {
		dir  string
		want int
	}{
		{sample("pass"), exitPass},
		{sample("fail"), exitFail},
		{sample("invalid"), exitError},
		{sample("sampels"), exitError}, // typo: no such directory
	}
	for _, tt := range tests {
		code, stdout, stderr := runCLI(t, "check", "--evidence", tt.dir)
		if code != tt.want {
			t.Errorf("%s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", tt.dir, code, tt.want, stdout, stderr)
		}
	}
}

func TestCheckPassShowsWaiver(t *testing.T) {
	_, stdout, _ := runCLI(t, "check", "--evidence", sample("pass"))
	for _, line := range []string{
		"evidence-gate dev | demo-app\n",
		"✓ TEST-002 coverage 88.2% (>= 80%)\n",
		"⚠ TEST-003 1 skipped test(s), waived by qa-lead until 2099-12-31: Rates API sandbox is down, tracked in #12\n",
		"RESULT: PASS (1 rule waived)\n",
		"evidence sha256: test-report ",
	} {
		if !strings.Contains(stdout, line) {
			t.Errorf("missing %q in:\n%s", line, stdout)
		}
	}
}

func TestCheckFailShowsFixes(t *testing.T) {
	_, stdout, _ := runCLI(t, "check", "--evidence", sample("fail"))
	for _, line := range []string{
		"✗ TEST-001 1 failed test(s)\n           fix: fix failing tests: TestCalculate/fixed_discount\n",
		"✗ TEST-002 coverage 72% (< 80%)\n           fix: raise coverage from 72% to at least 80%\n",
		"✗ TEST-003 1 skipped test(s)\n           fix: un-skip tests: TestQuoteLiveRates\n",
		"RESULT: FAIL (3 of ", // not "3 of 3": adding a rule must not break this test
	} {
		if !strings.Contains(stdout, line) {
			t.Errorf("missing %q in:\n%s", line, stdout)
		}
	}
}

func TestCheckJSON(t *testing.T) {
	code, stdout, _ := runCLI(t, "check", "--evidence", sample("fail"), "--json")
	if code != exitFail {
		t.Errorf("exit %d", code)
	}
	var got struct {
		Result        string `json:"result"`
		Project       string `json:"project"`
		PolicyVersion string `json:"policy_version"`
		Evidence      []struct {
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
		} `json:"evidence"`
		Violations []map[string]string `json:"violations"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, stdout)
	}
	if got.Result != "FAIL" || got.Project != "demo-app" || len(got.Violations) != 3 || len(got.PolicyVersion) != 64 {
		t.Errorf("got %+v", got)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].File != "test-report.json" || len(got.Evidence[0].SHA256) != 64 {
		t.Errorf("evidence %+v", got.Evidence)
	}
}

func TestCheckSummaryAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	if err := os.WriteFile(path, []byte("earlier step\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "check", "--evidence", sample("pass"), "--summary", path); code != exitPass {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.HasPrefix(got, "earlier step\n") || !strings.Contains(got, "| ⚠ | TEST-003 |") {
		t.Errorf("got:\n%s", got)
	}
}

func TestCheckPoliciesDir(t *testing.T) {
	code, _, stderr := runCLI(t, "check", "--evidence", sample("pass"), "--policies", filepath.Join("..", "..", "policies"))
	if code != exitPass {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

func TestCheckBrokenPolicyIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.rego"), []byte("package evidencegate\n\ndeny contains x if {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "check", "--evidence", sample("pass"), "--policies", dir)
	if code != exitError || !strings.Contains(stderr, "broken.rego") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		args []string
		want int
	}{
		{nil, exitError},
		{[]string{"deploy"}, exitError},
		{[]string{"check"}, exitError},
		{[]string{"check", "--evidence"}, exitError}, // flag without a value
		{[]string{"check", "-h"}, exitPass},
		{[]string{"help"}, exitPass},
	}
	for _, tt := range tests {
		if code, _, _ := runCLI(t, tt.args...); code != tt.want {
			t.Errorf("%v: exit %d, want %d", tt.args, code, tt.want)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCLI(t, "version")
	if code != exitPass || stdout != "evidence-gate dev\n" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
}

// write a file in dir and return its path
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// a fixed one-rule policy, so the test doesn't depend on the rules in policies/
const oneRulePolicy = `package evidencegate

rules := {"TEST-001": "no failed tests"}

deny contains {"rule": "TEST-001", "message": "failed tests", "fix": concat(", ", input.test_report.failed_tests)} if {
	input.test_report.summary.failed > 0
}

waived := set()
`

func TestCollectThenCheck(t *testing.T) {
	const pkg = "example.com/app"
	policies := t.TempDir()
	writeFile(t, policies, "gate.rego", oneRulePolicy)

	tests := []struct {
		name     string
		testJSON string
		profile  string
		want     int
		wantLine string
	}{
		{
			name:     "all pass",
			testJSON: `{"Action":"pass","Package":"` + pkg + `","Test":"TestA"}` + "\n" + `{"Action":"pass","Package":"` + pkg + `"}`,
			profile:  "mode: set\na.go:1.1,2.1 9 1\na.go:3.1,4.1 1 0\n",
			want:     exitPass,
			wantLine: "RESULT: PASS\n",
		},
		{
			name:     "failing test",
			testJSON: `{"Action":"fail","Package":"` + pkg + `","Test":"TestA"}` + "\n" + `{"Action":"fail","Package":"` + pkg + `"}`,
			profile:  "mode: set\na.go:1.1,2.1 9 1\na.go:3.1,4.1 1 0\n",
			want:     exitFail,
			wantLine: "fix: app.TestA\n",
		},
		{
			name:     "build failure",
			testJSON: `{"Action":"fail","Package":"` + pkg + `","FailedBuild":"` + pkg + `"}`,
			profile:  "mode: set\n",
			want:     exitFail,
			wantLine: "fix: app [build failed]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			testJSON := writeFile(t, dir, "test.json", tt.testJSON)
			profile := writeFile(t, dir, "coverage.out", tt.profile)
			evidence := filepath.Join(dir, "evidence")

			code, stdout, stderr := runCLI(t, "collect", "--test-json", testJSON, "--coverage", profile,
				"--project", "demo-app", "--commit", "abc1234", "--out", filepath.Join(evidence, "test-report.json"))
			if code != exitPass { // collect succeeds even when tests failed
				t.Fatalf("collect: exit %d\n%s%s", code, stdout, stderr)
			}

			code, stdout, stderr = runCLI(t, "check", "--evidence", evidence, "--policies", policies)
			if code != tt.want || !strings.Contains(stdout, tt.wantLine) {
				t.Errorf("check: exit %d, want %d; want %q in:\n%s%s", code, tt.want, tt.wantLine, stdout, stderr)
			}
		})
	}
}

func TestCollectErrors(t *testing.T) {
	dir := t.TempDir()
	testJSON := writeFile(t, dir, "test.json", `{"Action":"pass","Package":"p","Test":"TestA"}`)
	profile := writeFile(t, dir, "coverage.out", "mode: set\n")
	out := filepath.Join(dir, "test-report.json")

	tests := [][]string{
		{"collect"},
		{"collect", "--test-json", testJSON, "--coverage", profile, "--project", "p", "--out", out}, // no --commit
		{"collect", "--test-json", filepath.Join(dir, "nope.json"), "--coverage", profile, "--project", "p", "--commit", "c", "--out", out},
		{"collect", "--test-json", profile, "--coverage", profile, "--project", "p", "--commit", "c", "--out", out}, // not JSON
	}
	for _, args := range tests {
		if code, _, _ := runCLI(t, args...); code != exitError {
			t.Errorf("%v: exit %d, want 2", args[1:], code)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a failed collect must not write a report")
	}
}
