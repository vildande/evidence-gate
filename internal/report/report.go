// Package report renders the result of a check as text (terminal), JSON (tools)
// or Markdown (GitHub job summary). All three show the same rows in the same order.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vildande/evidence-gate/internal/audit"
	"github.com/vildande/evidence-gate/internal/policy"
	"github.com/vildande/evidence-gate/internal/schema"
)

// overall result of a check
const (
	Pass    = "PASS"
	Fail    = "FAIL"
	Invalid = "INVALID" // evidence did not match the schema, policies were not evaluated
)

// fingerprint of one evidence file
type Evidence struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// everything a check found
type Report struct {
	Version       string
	Project       string // "" when the test report could not be read
	CheckedAt     time.Time
	PolicyVersion string
	Schema        []schema.FileResult
	Policy        policy.Result // empty when the evidence is invalid
	Evidence      []Evidence
}

func (r Report) Result() string {
	for _, f := range r.Schema {
		if len(f.Issues) > 0 {
			return Invalid
		}
	}
	if len(r.Policy.Deny) > 0 {
		return Fail
	}
	return Pass
}

// row status
const (
	rowPass   = "pass"
	rowFail   = "fail"
	rowWaived = "waived"
)

// one line of output: a schema file or a rule
type row struct {
	status string
	label  string // "schema" or rule ID
	text   string // file name, pass text or violation message
	notes  []string
}

func schemaRows(r Report) []row {
	var rows []row
	for _, f := range r.Schema {
		rw := row{status: rowPass, label: "schema", text: f.File}
		for _, is := range f.Issues {
			rw.status = rowFail
			rw.notes = append(rw.notes, is.String())
		}
		rows = append(rows, rw)
	}
	return rows
}

// all rule IDs, sorted: the rules list plus any rule that has a violation
func ruleIDs(res policy.Result) []string {
	ids := make(map[string]bool)
	for id := range res.Rules {
		ids[id] = true
	}
	for _, v := range res.Deny {
		ids[v.Rule] = true // also list violations of rules missing from res.Rules
	}
	for _, w := range res.Waived {
		ids[w.Rule] = true
	}
	return slices.Sorted(maps.Keys(ids))
}

// every rule in ID order: failed, waived or passed. a rule can fail more than once
func ruleRows(res policy.Result) []row {
	var rows []row
	for _, id := range ruleIDs(res) {
		failed := false
		for _, v := range res.Deny {
			if v.Rule == id {
				rows = append(rows, row{status: rowFail, label: id, text: v.Message, notes: []string{"fix: " + v.Fix}})
				failed = true
			}
		}
		if failed {
			continue
		}

		waived := false
		for _, w := range res.Waived {
			if w.Rule == id {
				note := fmt.Sprintf("waived by %s until %s: %s", w.ApprovedBy, w.Expires, w.Reason)
				rows = append(rows, row{status: rowWaived, label: id, text: w.Message, notes: []string{note}})
				waived = true
			}
		}
		if waived {
			continue
		}

		rows = append(rows, row{status: rowPass, label: id, text: res.Rules[id]})
	}
	return rows
}

// "(1 of 3 rules failed)", "(1 rule waived)" or ""
func counts(res policy.Result) string {
	failed := make(map[string]bool)
	for _, v := range res.Deny {
		failed[v.Rule] = true
	}
	waived := make(map[string]bool)
	for _, w := range res.Waived {
		waived[w.Rule] = true
	}

	var parts []string
	if len(failed) > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d rules failed", len(failed), len(ruleIDs(res))))
	}
	if len(waived) > 0 {
		parts = append(parts, plural(len(waived), "rule")+" waived")
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func resultLine(r Report) string {
	switch r.Result() {
	case Invalid:
		return "RESULT: INVALID (evidence does not match the schema)"
	case Fail, Pass:
		if c := counts(r.Policy); c != "" {
			return "RESULT: " + r.Result() + " " + c
		}
	}
	return "RESULT: " + r.Result()
}

// "test-report 9a1f...c3 | waivers 4be0...7d"
func evidenceLine(r Report) string {
	var parts []string
	for _, e := range r.Evidence {
		parts = append(parts, strings.TrimSuffix(e.File, ".json")+" "+audit.Short(e.SHA256))
	}
	return strings.Join(parts, " | ")
}

func header(r Report) string {
	h := "evidence-gate " + r.Version
	if r.Project != "" {
		h += " | " + r.Project
	}
	return h
}

// ANSI colors, only used when the output is a terminal
const (
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

var symbols = map[string]string{rowPass: "✓", rowFail: "✗", rowWaived: "⚠"}
var colors = map[string]string{rowPass: green, rowFail: red, rowWaived: yellow}

// human-readable output
func WriteText(w io.Writer, r Report, color bool) error {
	paint := func(s, code string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	// built in memory, so there is one write and one error to check
	var sb strings.Builder
	sb.WriteString(header(r) + "\n\n")

	rows := schemaRows(r)
	if r.Result() != Invalid {
		rows = append(rows, ruleRows(r.Policy)...)
	}
	for _, rw := range rows {
		sym := paint(symbols[rw.status], colors[rw.status])
		switch rw.status {
		case rowWaived:
			// on one line, so a waived rule never looks like a plain pass
			fmt.Fprintf(&sb, "%s %-8s %s, %s\n", sym, rw.label, rw.text, rw.notes[0])
		default:
			fmt.Fprintf(&sb, "%s %-8s %s\n", sym, rw.label, rw.text)
			for _, n := range rw.notes {
				fmt.Fprintf(&sb, "%s %s\n", strings.Repeat(" ", 10), n) // indented under the text
			}
		}
	}

	resultColor := map[string]string{Pass: green, Fail: red, Invalid: red}[r.Result()]
	sb.WriteString("\n" + paint(resultLine(r), bold+resultColor) + "\n")
	if len(r.Evidence) > 0 {
		sb.WriteString("evidence sha256: " + evidenceLine(r) + "\n")
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

// machine-readable output
type jsonReport struct {
	Result        string             `json:"result"`
	Project       string             `json:"project"`
	CheckedAt     string             `json:"checked_at"`
	PolicyVersion string             `json:"policy_version"`
	Evidence      []Evidence         `json:"evidence"`
	Violations    []policy.Violation `json:"violations"`
	Waived        []policy.Waived    `json:"waived"`
	SchemaErrors  []schemaError      `json:"schema_errors,omitempty"` // only for INVALID
}

type schemaError struct {
	File    string `json:"file"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func WriteJSON(w io.Writer, r Report) error {
	out := jsonReport{
		Result:        r.Result(),
		Project:       r.Project,
		CheckedAt:     r.CheckedAt.UTC().Format(time.RFC3339),
		PolicyVersion: r.PolicyVersion,
		// empty lists, not null, so consumers can always loop over them
		Evidence:   orEmpty(r.Evidence),
		Violations: orEmpty(r.Policy.Deny),
		Waived:     orEmpty(r.Policy.Waived),
	}
	for _, f := range r.Schema {
		for _, is := range f.Issues {
			out.SchemaErrors = append(out.SchemaErrors, schemaError{File: f.File, Path: is.Path, Message: is.Message})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep "< 80%" readable instead of "< 80%"
	return enc.Encode(out)
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// GitHub job summary, appended to $GITHUB_STEP_SUMMARY
func WriteMarkdown(w io.Writer, r Report) error {
	var sb strings.Builder
	sb.WriteString("### " + header(r) + "\n\n")
	sb.WriteString("| | Check | Result |\n| --- | --- | --- |\n")

	rows := schemaRows(r)
	if r.Result() != Invalid {
		rows = append(rows, ruleRows(r.Policy)...)
	}
	for _, rw := range rows {
		cell := escape(rw.text)
		for _, n := range rw.notes {
			if rw.status == rowWaived {
				cell += ", " + escape(n)
			} else {
				cell += "<br>" + escape(n)
			}
		}
		fmt.Fprintf(&sb, "| %s | %s | %s |\n", symbols[rw.status], rw.label, cell)
	}

	sb.WriteString("\n**" + escape(resultLine(r)) + "**\n\n")
	if len(r.Evidence) > 0 {
		sb.WriteString("evidence sha256: " + escape(evidenceLine(r)) + "\n\n")
	}

	_, err := io.WriteString(w, sb.String())
	return err
}

// make text safe inside a Markdown table cell
func escape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"|", `\|`,
		"\n", "<br>",
	).Replace(s)
}
