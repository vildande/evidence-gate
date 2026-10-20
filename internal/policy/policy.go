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

// both sets in one query: violations that block, and violations that are waived
const query = "deny := data.evidencegate.deny; waived := data.evidencegate.waived"

// a failed rule, as produced by a deny rule in Rego
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

// a failed rule that passes because of a valid waiver
type Waived struct {
	Rule       string `json:"rule"`
	Message    string `json:"message"`
	ApprovedBy string `json:"approved_by"`
	Reason     string `json:"reason"`
	Expires    string `json:"expires"`
}

// outcome of the policies. empty Deny = PASS, even if some rules are waived
type Result struct {
	Deny   []Violation
	Waived []Waived
}

// input for the OPA policies
type Input struct {
	TestReport any    `json:"test_report"`
	Waivers    any    `json:"waivers"`
	Now        string `json:"now"` // date of now, "YYYY-MM-DD"
}

// contains ready-to-use OPA query
type Engine struct {
	query rego.PreparedEvalQuery
}

// read all .rego files in dir, except *_test.rego
func LoadDir(dir string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.rego")) // find all .rego files in the directory
	if err != nil {
		return nil, err
	}

	modules := make(map[string]string)
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.rego") { // skip test files
			continue
		}

		// read the file and add it to the map
		src, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		modules[filepath.Base(p)] = string(src)
	}

	// no policies found
	if len(modules) == 0 {
		return nil, fmt.Errorf("policies: no .rego files in %s", dir)
	}
	return modules, nil
}

// prepare the OPA query
func Compile(ctx context.Context, modules map[string]string) (*Engine, error) {

	opts := []func(*rego.Rego){
		rego.Query(query), // we add our query
		rego.StrictBuiltinErrors(true), // use sctrict errors
	}

	// sorted by filename
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		opts = append(opts, rego.Module(name, modules[name])) // add the module
	}

	// prepare the query for eval 
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Engine{query: q}, nil
}


// evaluate the policies on an input.
// get deny and waived, both sorted by rule.
func (e *Engine) Eval(ctx context.Context, in Input) (Result, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(in)) // run th query with the input
	if err != nil {
		return Result{}, err
	}

	// no results means deny or waived is missing
	if len(rs) == 0 {
		return Result{}, errors.New("policies: package evidencegate must define deny and waived")
	}

	var res Result
	if err := fromOPA(rs[0].Bindings["deny"], &res.Deny); err != nil {
		return Result{}, fmt.Errorf("policies: deny must contain {rule, message, fix} objects: %w", err)
	}
	if err := fromOPA(rs[0].Bindings["waived"], &res.Waived); err != nil {
		return Result{}, fmt.Errorf("policies: waived must contain {rule, message, approved_by, reason, expires} objects: %w", err)
	}

	slices.SortFunc(res.Deny, func(a, b Violation) int { // sort violations by rule, then message, then fix
		return cmp.Or(
			cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Message, b.Message),
			cmp.Compare(a.Fix, b.Fix),
		)
	})
	slices.SortFunc(res.Waived, func(a, b Waived) int { // same rule can have several waivers, so compare every field
		return cmp.Or(
			cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Message, b.Message),
			cmp.Compare(a.Expires, b.Expires),
			cmp.Compare(a.ApprovedBy, b.ApprovedBy),
			cmp.Compare(a.Reason, b.Reason),
		)
	})
	return res, nil
}

// result OPA -> json -> Go struct (if cannot transform, then error)
func fromOPA(v any, out any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// build the policy input from an evidence directory.
// call AFTER schema validation, which guarantees the files exist and have the right shape
func ReadInput(dir, now string) (Input, error) {
	in := Input{Now: now, Waivers: []any{}} // waivers might be missing

	var err error
	if in.TestReport, err = readJSON(filepath.Join(dir, "test-report.json")); err != nil { // read. no test-report, then error
		return Input{}, err
	}

	// if waivers exists add, otherwise leave empty
	w, err := readJSON(filepath.Join(dir, "waivers.json"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// optional file
	case err != nil:
		return Input{}, err
	default:
		in.Waivers = w
	}
	return in, nil
}



func readJSON(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data)) // decoder: data -> JSON
	dec.UseNumber() // UseNumber keeps numbers as written (86.1 stays 86.1), instead of float64
	var v any
	if err := dec.Decode(&v); err != nil { // decode data -> JSON
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}
