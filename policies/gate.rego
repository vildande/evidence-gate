# gate rules. each rule adds a violation to deny; empty deny = PASS
#
# input: {"test_report", "exceptions", "now"}
# now is a "YYYY-MM-DD" date passed in by the caller, so results never depend on the clock
package evidencegate

min_coverage := 80

# TEST-001: no failed tests. exceptions do not apply: failing tests always block
deny contains {
	"rule": "TEST-001",
	"message": sprintf("%d failed test(s)", [input.test_report.summary.failed]),
	"fix": sprintf("fix failing tests: %s", [concat(", ", input.test_report.failed_tests)]),
} if {
	input.test_report.summary.failed > 0
}

# TEST-002: coverage >= min_coverage
deny contains {
	"rule": "TEST-002",
	"message": sprintf("coverage %v%% is below %v%%", [cov, min_coverage]),
	"fix": sprintf("raise coverage from %v%% to at least %v%%", [cov, min_coverage]),
} if {
	cov := input.test_report.coverage_percent
	cov < min_coverage
}

# TEST-003: each skipped test needs an exception that has not expired yet
deny contains {
	"rule": "TEST-003",
	"message": sprintf("skipped test %s has no valid exception", [name]),
	"fix": sprintf("un-skip %s, or add an exception with reason, approver, expiry", [name]),
} if {
	some name in input.test_report.skipped_tests
	not has_valid_exception(name)
}

# "YYYY-MM-DD" strings sort like dates, so plain string comparison works.
# an exception that expires today is already expired
has_valid_exception(test) if {
	some e in input.exceptions
	e.test == test
	e.expires > input.now
}
