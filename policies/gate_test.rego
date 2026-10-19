# unit tests for gate.rego, run with: opa test policies/
# each rule has at least one passing and one failing case
package evidencegate_test

import data.evidencegate

# builders for small inputs, so each test only shows what it changes

report(failed, names, coverage) := {
	"summary": {"total": 10, "passed": 10 - failed, "failed": failed, "skipped": 0},
	"coverage_percent": coverage,
	"failed_tests": names,
}

finding(id, pkg, severity) := {
	"id": id, "package": pkg,
	"installed_version": "1.0.0", "fixed_version": "1.0.1",
	"severity": severity,
}

exception(cve, expires) := {"cve": cve, "reason": "r", "approved_by": "security-team", "expires": expires}

gate_input(tr, findings, exceptions) := {
	"test_report": tr,
	"vuln_scan": {"findings": findings},
	"exceptions": exceptions,
	"now": "2026-10-19",
}

good_report := report(0, [], 85)

# set of rule IDs that fired
fired(deny) := {v.rule | some v in deny}

test_clean_input_passes if {
	inp := gate_input(good_report, [finding("CVE-1", "zlib", "LOW")], [])
	count(evidencegate.deny) == 0 with input as inp
}

# TEST-001

test_test001_passes_with_no_failed_tests if {
	inp := gate_input(good_report, [], [])
	deny := evidencegate.deny with input as inp
	not "TEST-001" in fired(deny)
}

test_test001_lists_failing_tests if {
	inp := gate_input(report(2, ["TestA", "TestB"], 85), [], [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-001"
	v.message == "2 failed test(s)"
	v.fix == "fix failing tests: TestA, TestB"
}

# TEST-002

test_test002_passes_at_exactly_80 if {
	inp := gate_input(report(0, [], 80), [], [])
	deny := evidencegate.deny with input as inp
	not "TEST-002" in fired(deny)
}

test_test002_shows_current_and_required if {
	inp := gate_input(report(0, [], 72.5), [], [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "TEST-002"
	v.fix == "raise coverage from 72.5% to at least 80%"
}

# VULN-001

test_vuln001_passes_without_critical if {
	inp := gate_input(good_report, [finding("CVE-1", "zlib", "MEDIUM")], [])
	deny := evidencegate.deny with input as inp
	not "VULN-001" in fired(deny)
}

test_vuln001_suggests_upgrade if {
	inp := gate_input(good_report, [finding("CVE-1", "openssl", "CRITICAL")], [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "VULN-001"
	v.message == "critical vulnerability CVE-1 in openssl 1.0.0"
	v.fix == "upgrade openssl to >= 1.0.1"
}

test_vuln001_ignores_exceptions if {
	inp := gate_input(good_report, [finding("CVE-1", "openssl", "CRITICAL")], [exception("CVE-1", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	"VULN-001" in fired(deny)
}

test_vuln001_without_fixed_version if {
	f := object.union(finding("CVE-1", "openssl", "CRITICAL"), {"fixed_version": ""})
	inp := gate_input(good_report, [f], [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "VULN-001"
	v.fix == "no fixed version of openssl yet: remove or replace it"
}

# VULN-002

test_vuln002_passes_with_valid_exception if {
	inp := gate_input(good_report, [finding("CVE-1", "libxml2", "HIGH")], [exception("CVE-1", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	not "VULN-002" in fired(deny)
}

test_vuln002_fails_without_exception if {
	inp := gate_input(good_report, [finding("CVE-1", "libxml2", "HIGH")], [])
	deny := evidencegate.deny with input as inp
	some v in deny
	v.rule == "VULN-002"
	v.fix == "upgrade libxml2 to >= 1.0.1, or add an exception with reason, approver, expiry"
}

test_vuln002_fails_with_expired_exception if {
	inp := gate_input(good_report, [finding("CVE-1", "libxml2", "HIGH")], [exception("CVE-1", "2026-10-01")])
	deny := evidencegate.deny with input as inp
	"VULN-002" in fired(deny)
}

test_vuln002_fails_when_exception_expires_today if {
	inp := gate_input(good_report, [finding("CVE-1", "libxml2", "HIGH")], [exception("CVE-1", "2026-10-19")])
	deny := evidencegate.deny with input as inp
	"VULN-002" in fired(deny)
}

test_vuln002_exception_for_other_cve_does_not_count if {
	inp := gate_input(good_report, [finding("CVE-1", "libxml2", "HIGH")], [exception("CVE-2", "2026-12-31")])
	deny := evidencegate.deny with input as inp
	"VULN-002" in fired(deny)
}
