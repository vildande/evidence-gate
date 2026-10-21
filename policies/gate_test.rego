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

waiver(rule, expires) := {"rule": rule, "reason": "r", "approved_by": "qa-lead", "expires": expires}

gate_input(tr, waivers) := {
	"test_report": tr,
	"waivers": waivers,
	"now": "2026-10-19",
}

good_report := report(0, [], 85)

# set of rule IDs that fired
fired(set) := {v.rule | some v in set}

test_clean_input_passes if {
	inp := gate_input(good_report, [])
	count(evidencegate.deny) == 0 with input as inp
	count(evidencegate.waived) == 0 with input as inp
}

# rules

test_rules_list_every_rule if {
	inp := gate_input(good_report, [])
	rules := evidencegate.rules with input as inp
	rules == {
		"TEST-001": "no failed tests",
		"TEST-002": "coverage 85% (>= 80%)",
		"TEST-003": "no skipped tests",
	}
}

# a new rule must be added to rules too, or check could not list it as passing
test_every_violation_is_in_rules if {
	inp := gate_input(object.union(report(1, ["TestA"], 50), {"skipped_tests": ["TestB"]}), [])
	violations := evidencegate.violation with input as inp
	rules := evidencegate.rules with input as inp
	count(violations) == 3
	every v in violations {
		v.rule in object.keys(rules)
	}
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
	v.message == "coverage 72.5% (< 80%)"
	v.fix == "raise coverage from 72.5% to at least 80%"
}

# TEST-003

test_test003_passes_with_no_skipped_tests if {
	inp := gate_input(good_report, [])
	deny := evidencegate.deny with input as inp
	not "TEST-003" in fired(deny)
}

test_test003_lists_skipped_tests if {
	inp := gate_input(skipped(["TestA", "TestB"]), [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-003"
	v.message == "2 skipped test(s)"
	v.fix == "un-skip tests: TestA, TestB"
}

# waivers

test_valid_waiver_passes_and_shows_as_waived if {
	inp := gate_input(report(0, [], 75), [waiver("TEST-002", "2026-10-27")])
	deny := evidencegate.deny with input as inp
	waived := evidencegate.waived with input as inp
	count(deny) == 0
	waived == {{
		"rule": "TEST-002",
		"message": "coverage 75% (< 80%)",
		"approved_by": "qa-lead",
		"reason": "r",
		"expires": "2026-10-27",
	}}
}

test_expired_waiver_blocks if {
	inp := gate_input(report(0, [], 75), [waiver("TEST-002", "2026-10-01")])
	deny := evidencegate.deny with input as inp
	waived := evidencegate.waived with input as inp
	"TEST-002" in fired(deny)
	count(waived) == 0
}

test_waiver_expiring_today_blocks if {
	inp := gate_input(report(0, [], 75), [waiver("TEST-002", "2026-10-19")])
	deny := evidencegate.deny with input as inp
	"TEST-002" in fired(deny)
}

test_waiver_for_another_rule_does_not_apply if {
	inp := gate_input(report(0, [], 75), [waiver("TEST-001", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	waived := evidencegate.waived with input as inp
	"TEST-002" in fired(deny)
	count(waived) == 0
}

test_waiver_covers_only_its_rule if {
	inp := gate_input(report(1, ["TestA"], 75), [waiver("TEST-002", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	waived := evidencegate.waived with input as inp
	fired(deny) == {"TEST-001"}
	fired(waived) == {"TEST-002"}
}

test_each_matching_waiver_shows_in_waived if {
	waivers := [waiver("TEST-002", "2026-10-27"), object.union(waiver("TEST-002", "2026-11-30"), {"approved_by": "cto"})]
	inp := gate_input(report(0, [], 75), waivers)
	waived := evidencegate.waived with input as inp
	{w.approved_by | some w in waived} == {"qa-lead", "cto"}
}
