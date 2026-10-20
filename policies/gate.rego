# gate rules. each rule adds to violation; violations without a valid waiver go to deny.
# empty deny = PASS
#
# input: {"test_report", "waivers", "now"}
# now is a "YYYY-MM-DD" date passed in by the caller, so results never depend on the clock
package evidencegate

min_coverage := 80

# every rule ID with the text shown when it passes, so check can list passing rules too
rules := {
	"TEST-001": "no failed tests",
	"TEST-002": sprintf("coverage %v%% (≥ %v%%)", [input.test_report.coverage_percent, min_coverage]),
	"TEST-003": "no skipped tests",
}

# TEST-001: no failed tests
violation contains {
	"rule": "TEST-001",
	"message": sprintf("%d failed test(s)", [input.test_report.summary.failed]),
	"fix": sprintf("fix failing tests: %s", [concat(", ", input.test_report.failed_tests)]),
} if {
	input.test_report.summary.failed > 0
}

# TEST-002: coverage >= min_coverage
violation contains {
	"rule": "TEST-002",
	"message": sprintf("coverage %v%% (< %v%%)", [cov, min_coverage]),
	"fix": sprintf("raise coverage from %v%% to at least %v%%", [cov, min_coverage]),
} if {
	cov := input.test_report.coverage_percent
	cov < min_coverage
}

# TEST-003: no skipped tests
violation contains {
	"rule": "TEST-003",
	"message": sprintf("%d skipped test(s)", [count(input.test_report.skipped_tests)]),
	"fix": sprintf("un-skip tests: %s", [concat(", ", input.test_report.skipped_tests)]),
} if {
	count(input.test_report.skipped_tests) > 0
}

# violations that block the PR
deny contains v if {
	some v in violation
	not has_valid_waiver(v.rule)
}

# violations that pass because of a waiver, kept visible for auditors.
# one entry per matching waiver, so every approval that applies is shown
waived contains {
	"rule": v.rule,
	"message": v.message,
	"approved_by": w.approved_by,
	"reason": w.reason,
	"expires": w.expires,
} if {
	some v in violation
	some w in valid_waivers
	w.rule == v.rule
}

# "YYYY-MM-DD" strings sort like dates, so plain string comparison works.
# a waiver that expires today is already expired
valid_waivers contains w if {
	some w in input.waivers
	w.expires > input.now
}

has_valid_waiver(rule) if {
	some w in valid_waivers
	w.rule == rule
}
