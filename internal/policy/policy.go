// Package policy loads Rego policies and evaluates them with embedded OPA.
// It returns the list of violations; an empty list means PASS.
package policy

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
)

// query asks for the set of violations produced by all deny rules
const query = "data.evidencegate.deny"

// one failed rule, as produced by a deny rule in Rego
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

// the document policies see as `input`. evidence is kept as parsed JSON (any),
// so policies read exactly what is in the files
type Input struct {
	TestReport any    `json:"test_report"`
	VulnScan   any    `json:"vuln_scan"`
	Exceptions any    `json:"exceptions"`
	Now        string `json:"now"` // "YYYY-MM-DD"
}

// compiled policies, ready to evaluate many inputs
type Engine struct {
	query rego.PreparedEvalQuery
}

// read all .rego files in dir, except *_test.rego.
// returns file name -> source, so callers can add a draft module before compiling
func LoadDir(dir string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil {
		return nil, err
	}

	modules := make(map[string]string)
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.rego") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		modules[filepath.Base(p)] = string(src)
	}

	// no policies would mean every check passes, so treat it as an error
	if len(modules) == 0 {
		return nil, fmt.Errorf("policies: no .rego files in %s", dir)
	}
	return modules, nil
}

// compile the modules. a compile error names the file and line
func Compile(ctx context.Context, modules map[string]string) (*Engine, error) {
	opts := []func(*rego.Rego){
		rego.Query(query),
		// a builtin error (e.g. sprintf on a missing field) must stop the check.
		// by default OPA treats it as "rule not matched", which would silently pass
		rego.StrictBuiltinErrors(true),
	}
	// sorted, so compile errors come out in the same order every run
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		opts = append(opts, rego.Module(name, modules[name]))
	}

	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Engine{query: q}, nil
}

// evaluate the policies on one input. violations are sorted by rule, then message
func (e *Engine) Eval(ctx context.Context, in Input) ([]Violation, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return nil, err
	}

	// no result means the package or deny rule is missing, not that everything passed
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("policies: no deny rules found in package evidencegate")
	}

	// OPA returns generic JSON values; a round trip through JSON turns them into
	// Violations and rejects any deny entry that has the wrong shape
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var violations []Violation
	if err := json.Unmarshal(raw, &violations); err != nil {
		return nil, fmt.Errorf("policies: deny must contain {rule, message, fix} objects: %w", err)
	}

	slices.SortFunc(violations, func(a, b Violation) int {
		return cmp.Or(
			cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Message, b.Message),
			cmp.Compare(a.Fix, b.Fix),
		)
	})
	return violations, nil
}

// build the policy input from an evidence directory.
// call after schema validation, which guarantees the files exist and have the right shape
func ReadInput(dir, now string) (Input, error) {
	in := Input{Now: now, Exceptions: []any{}} // no exceptions.json = no exceptions

	var err error
	if in.TestReport, err = readJSON(filepath.Join(dir, "test-report.json")); err != nil {
		return Input{}, err
	}
	if in.VulnScan, err = readJSON(filepath.Join(dir, "vuln-scan.json")); err != nil {
		return Input{}, err
	}

	exc, err := readJSON(filepath.Join(dir, "exceptions.json"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// optional file
	case err != nil:
		return Input{}, err
	default:
		in.Exceptions = exc
	}
	return in, nil
}

// UseNumber keeps numbers as written (86.1 stays 86.1), instead of float64
func readJSON(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}
