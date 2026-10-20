# unit tests for gate.rego, run with: opa test policies/
# each rule has at least one passing and one failing case
package evidencegate_test

import data.evidencegate

# builders for small inputs, so each test only shows what it changes

report(failed, names, coverage) := {
	"summary": {"total": 10, "passed": 10 - failed, "failed": failed, "skipped": 0},
	"coverage_percent": coverage,
	"failed_tests": names,
	"skipped_tests": [],
}

# report with skipped tests
skipped(names) := object.union(good_report, {"skipped_tests": names})

exception(test, expires) := {"test": test, "reason": "r", "approved_by": "qa-lead", "expires": expires}

gate_input(tr, exceptions) := {
	"test_report": tr,
	"exceptions": exceptions,
	"now": "2026-10-19",
}

good_report := report(0, [], 85)

# set of rule IDs that fired
fired(deny) := {v.rule | some v in deny}

test_clean_input_passes if {
	inp := gate_input(skipped(["TestA"]), [exception("TestA", "2026-12-31")])
	count(evidencegate.deny) == 0 with input as inp
}

# TEST-001

test_test001_passes_with_no_failed_tests if {
	inp := gate_input(good_report, [])
	deny := evidencegate.deny with input as inp
	not "TEST-001" in fired(deny)
}

test_test001_lists_failing_tests if {
	inp := gate_input(report(2, ["TestA", "TestB"], 85), [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-001"
	v.message == "2 failed test(s)"
	v.fix == "fix failing tests: TestA, TestB"
}

# TEST-002

test_test002_passes_at_exactly_80 if {
	inp := gate_input(report(0, [], 80), [])
	deny := evidencegate.deny with input as inp
	not "TEST-002" in fired(deny)
}

test_test002_shows_current_and_required if {
	inp := gate_input(report(0, [], 72.5), [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-002"
	v.fix == "raise coverage from 72.5% to at least 80%"
}

# TEST-003

test_test003_passes_with_valid_exception if {
	inp := gate_input(skipped(["TestA"]), [exception("TestA", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	not "TEST-003" in fired(deny)
}

test_test003_fails_without_exception if {
	inp := gate_input(skipped(["TestA"]), [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-003"
	v.message == "skipped test TestA has no valid exception"
	v.fix == "un-skip TestA, or add an exception with reason, approver, expiry"
}

test_test003_fails_with_expired_exception if {
	inp := gate_input(skipped(["TestA"]), [exception("TestA", "2026-10-01")])
	deny := evidencegate.deny with input as inp
	"TEST-003" in fired(deny)
}

test_test003_fails_when_exception_expires_today if {
	inp := gate_input(skipped(["TestA"]), [exception("TestA", "2026-10-19")])
	deny := evidencegate.deny with input as inp
	"TEST-003" in fired(deny)
}

test_test003_exception_for_other_test_does_not_count if {
	inp := gate_input(skipped(["TestA"]), [exception("TestB", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	"TEST-003" in fired(deny)
}

test_test003_one_violation_per_unexcepted_skip if {
	inp := gate_input(skipped(["TestA", "TestB", "TestC"]), [exception("TestB", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	count({v | some v in deny; v.rule == "TEST-003"}) == 2
}

test_exceptions_do_not_waive_failed_tests if {
	inp := gate_input(report(1, ["TestA"], 85), [exception("TestA", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	"TEST-001" in fired(deny)
}
