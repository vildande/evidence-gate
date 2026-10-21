# evidence-gate

A CI gate that blocks a pull request unless its test evidence passes JSON Schema validation and Rego policies.

## How it works

Every pull request to this repo runs these steps in GitHub Actions:

1. Run the tests of `demo-app`, a small pricing service in this repo, with `go test -json -coverprofile`.
2. `evidence-gate collect` turns the output into `test-report.json`.
3. `evidence-gate check` validates the evidence against JSON Schemas. Invalid evidence is rejected on this step.
4. `check` evaluates the Rego policies. A violation (without a waiver) fails the job.
5. Branch protection in GitHub Actions requires the job to pass, so the pull request cannot be merged.

Exit codes: `0` pass, `1` policy failure, `2` invalid or missing evidence, or any other error.

## Policies and waivers

The rules are in [policies/gate.rego](policies/gate.rego). They are bundled into the binary; `check --policies dir` uses another directory.

| ID       | Rule                                                              | Fix hint                |
| -------- | ----------------------------------------------------------------- | ----------------------- |
| TEST-001 | no failed tests; a package that does not compile counts as failed | lists the failing tests |
| TEST-002 | coverage >= 80%                                                   | current vs required     |
| TEST-003 | no skipped tests                                                  | lists the skipped tests |

A waiver lets pull requests pass one rule until a date. It goes in an optional `waivers.json` next to the evidence; in this repo that is `demo-app/waivers.json`:

```json
[ { "rule": "TEST-002", "reason": "Receipt formatting ships before its tests, tests follow next sprint",
    "approved_by": "qa-lead", "expires": "2026-11-30" } ]
```

- All four fields are required and checked by the schema.
- A waiver covers every violation of its rule, on every pull request, until `expires`. On that date it no longer applies.
- Waived violations are never shown as a pass: they get a ⚠ row in the output and job summary, and a `waived` list in `--json`.

## See it in action

Four demo pull requests, left open on purpose. Open the `gate` check on each to see the job summary.

| PR                                                    | Change                                             | Gate                |
| ----------------------------------------------------- | -------------------------------------------------- | ------------------- |
| [#1](https://github.com/vildande/evidence-gate/pull/1) | breaks one test assertion                          | FAIL on TEST-001    |
| [#2](https://github.com/vildande/evidence-gate/pull/2) | adds an untested function, coverage drops to 73.8% | FAIL on TEST-002    |
| [#3](https://github.com/vildande/evidence-gate/pull/3) | same code as#2, plus a waiver for TEST-002         | PASS, 1 rule waived |
| [#4](https://github.com/vildande/evidence-gate/pull/4) | adds a discount code with tests                    | PASS                |

## What the gate prints

The `gate` job prints this in its log and job summary. The output below is the same check.

PR #1, a broken test. The pull request is blocked and the output says what to fix:

```
evidence-gate dev | demo-app

✓ schema   test-report.json
✗ TEST-001 1 failed test(s)
           fix: fix failing tests: pricing.TestCalculate/fixed_discount
✓ TEST-002 coverage 88.2% (>= 80%)
✓ TEST-003 no skipped tests

RESULT: FAIL (1 of 3 rules failed)
evidence sha256: test-report 3da0...5f
```

PR #2, an untested function. Coverage drops below 80%, so the pull request is blocked:

```
evidence-gate dev | demo-app

✓ schema   test-report.json
✓ TEST-001 no failed tests
✗ TEST-002 coverage 73.8% (< 80%)
           fix: raise coverage from 73.8% to at least 80%
✓ TEST-003 no skipped tests

RESULT: FAIL (1 of 3 rules failed)
evidence sha256: test-report 3ea2...8a
```

PR #3, coverage below 80% with a waiver. The pull request passes:

```
evidence-gate dev | demo-app

✓ schema   test-report.json
✓ schema   waivers.json
✓ TEST-001 no failed tests
⚠ TEST-002 coverage 73.8% (< 80%), waived by qa-lead until 2026-11-30: Receipt formatting ships before its tests, tests follow next sprint
✓ TEST-003 no skipped tests

RESULT: PASS (1 rule waived)
evidence sha256: test-report 415a...e0 | waivers 9d55...b7
```

PR #4, a new feature with tests. Every rule passes and the pull request can be merged:

```
evidence-gate dev | demo-app

✓ schema   test-report.json
✓ TEST-001 no failed tests
✓ TEST-002 coverage 89.1% (>= 80%)
✓ TEST-003 no skipped tests

RESULT: PASS
evidence sha256: test-report cbf5...82
```

## CI workflows

| File                                        | What it does                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ci.yml](.github/workflows/ci.yml)           | Runs on every pull request and push to`main`. Job `tool` tests evidence-gate itself: `go vet`, `go test`, `opa test`, and checks that the samples exit 0, 1 and 2. Job `gate` runs the `demo-app` tests, collects the evidence, runs the gate and uploads the evidence as a build artifact. |
| [action.yml](action.yml)                     | Used by the`gate` job with `uses: ./`. Sets up Go, builds evidence-gate, runs `check` on the evidence and writes the result to the job summary. Exit 1 or 2 fails the job.                                                                                                                          |
| [release.yml](.github/workflows/release.yml) | Runs on a version tag. Builds binaries for macOS, Linux and Windows, publishes them as a[GitHub Release](https://github.com/vildande/evidence-gate/releases) and moves the `v1` tag.                                                                                                                     |

## Merge blocking (ruleset in GitHub repo)

A failed check only blocks merging if the repository requires it. That's why `main` branch has a repository ruleset that:

- requires a pull request, so nobody pushes to `main` directly
- requires the checks `tool` and `gate` to pass
- blocks force pushes and deleting `main`

This is why, for example, PRs #1 and #2 cannot be merged.

## Run it locally (if you want to)

You can do the same steps as the `gate` job, locally, from the repo root. Needs Go 1.27 or newer.

```bash
rm -rf evidence && mkdir evidence
(cd demo-app && go test -json -coverprofile=../evidence/coverage.out ./... > ../evidence/test.json || true)
go run ./cmd/evidence-gate collect --test-json evidence/test.json --coverage evidence/coverage.out \
  --project demo-app --commit "$(git rev-parse --short HEAD)" --out evidence/test-report.json
if [ -f demo-app/waivers.json ]; then cp demo-app/waivers.json evidence/; fi
go run ./cmd/evidence-gate check --evidence evidence
```

On `main` this passes. To try a demo pull request, switch to its branch first, for example `git switch demo/broken-test`:

| Branch                   | PR | Result              |
| ------------------------ | -- | ------------------- |
| `demo/broken-test`     | #1 | FAIL on TEST-001    |
| `demo/coverage-drop`   | #2 | FAIL on TEST-002    |
| `demo/coverage-waived` | #3 | PASS, 1 rule waived |
| `demo/clean-feature`   | #4 | PASS                |

## License

[MIT](LICENSE)