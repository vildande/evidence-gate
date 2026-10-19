# gate rules. each rule adds a violation to deny; empty deny = PASS
#
# input: {"test_report", "vuln_scan", "exceptions", "now"}
# now is a "YYYY-MM-DD" date passed in by the caller, so results never depend on the clock
package evidencegate

min_coverage := 80

# TEST-001: no failed tests
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

# VULN-001: no CRITICAL findings, exceptions do not apply
deny contains {
	"rule": "VULN-001",
	"message": sprintf("critical vulnerability %s in %s %s", [f.id, f.package, f.installed_version]),
	"fix": upgrade_hint(f),
} if {
	some f in input.vuln_scan.findings
	f.severity == "CRITICAL"
}

# VULN-002: HIGH findings need an exception that has not expired yet
deny contains {
	"rule": "VULN-002",
	"message": sprintf("high vulnerability %s in %s %s has no valid exception", [f.id, f.package, f.installed_version]),
	"fix": sprintf("%s, or add an exception with reason, approver, expiry", [upgrade_hint(f)]),
} if {
	some f in input.vuln_scan.findings
	f.severity == "HIGH"
	not has_valid_exception(f.id)
}

# "YYYY-MM-DD" strings sort like dates, so plain string comparison works.
# an exception that expires today is already expired
has_valid_exception(cve) if {
	some e in input.exceptions
	e.cve == cve
	e.expires > input.now
}

upgrade_hint(f) := sprintf("upgrade %s to >= %s", [f.package, f.fixed_version]) if {
	f.fixed_version != ""
}

# the schema allows an empty fixed_version: the scanner knows no fix yet
upgrade_hint(f) := sprintf("no fixed version of %s yet: remove or replace it", [f.package]) if {
	f.fixed_version == ""
}
