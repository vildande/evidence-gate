// Package schema checks evidence files against the bundled JSON Schemas.
//
// Validation runs before any policy is evaluated: a policy can only give a
// trustworthy answer if the data it reads has the shape it expects. A typo
// like "coverage_pct" would otherwise be silently missing and could make a
// rule pass when it should fail.
package schema

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/vildande/evidence-gate/schemas"
)

// schemaFor maps each evidence file name to the schema it must satisfy.
var schemaFor = map[string]string{
	"test-report.json": "test-report.schema.json",
	"vuln-scan.json":   "vuln-scan.schema.json",
	"exceptions.json":  "exceptions.schema.json",
}

// optional lists evidence files a project may leave out. A project with no
// exceptions simply has no exceptions.json; that is not an error.
var optional = map[string]bool{
	"exceptions.json": true,
}

// Issue is one problem found in an evidence file.
type Issue struct {
	Path    string // JSON pointer into the document, e.g. "/summary/failed"; "" for the whole file
	Message string
}

func (i Issue) String() string {
	if i.Path == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

// Validator holds the compiled schemas. Compile once, validate many files.
type Validator struct {
	schemas map[string]*jsonschema.Schema // keyed by evidence file name
}

// New compiles the schemas embedded in the binary.
func New() (*Validator, error) {
	c := jsonschema.NewCompiler()
	// In draft 2020-12 "format" is only an annotation by default, which would
	// let "generated_at": "yesterday" through. We want it enforced.
	c.AssertFormat()

	v := &Validator{schemas: make(map[string]*jsonschema.Schema)}
	for evidenceFile, schemaFile := range schemaFor {
		data, err := fs.ReadFile(schemas.FS, schemaFile)
		if err != nil {
			return nil, fmt.Errorf("read schema %s: %w", schemaFile, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parse schema %s: %w", schemaFile, err)
		}
		// The compiler identifies schemas by URL; a fake file URL is enough
		// because we never let it fetch anything from the network.
		url := "file:///schemas/" + schemaFile
		if err := c.AddResource(url, doc); err != nil {
			return nil, fmt.Errorf("add schema %s: %w", schemaFile, err)
		}
		compiled, err := c.Compile(url)
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", schemaFile, err)
		}
		v.schemas[evidenceFile] = compiled
	}
	return v, nil
}

// Files returns the evidence file names that have a schema, in a stable order.
func (v *Validator) Files() []string {
	return slices.Sorted(maps.Keys(v.schemas))
}

// Validate checks the contents of one evidence file. An empty result means
// the file is valid. Malformed JSON is reported as an Issue, not an error,
// because to the user it is the same kind of problem: bad evidence.
// The error is only for misuse, such as a file name with no schema.
func (v *Validator) Validate(fileName string, data []byte) ([]Issue, error) {
	sch, ok := v.schemas[fileName]
	if !ok {
		return nil, fmt.Errorf("no schema for evidence file %q", fileName)
	}

	// UnmarshalJSON keeps numbers as json.Number, so the validator can tell
	// 3 (integer) from 3.5 (not an integer) exactly.
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return []Issue{{Message: "not valid JSON: " + err.Error()}}, nil
	}

	err = sch.Validate(doc)
	if err == nil {
		return nil, nil
	}
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return nil, err
	}

	var issues []Issue
	collectLeaves(verr, &issues)
	// Stable, so issues at the same path keep the library's order and the
	// output is identical on every run.
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	return issues, nil
}

// FileResult is the outcome of validating one evidence file.
type FileResult struct {
	File   string
	Issues []Issue // empty means valid
}

// ValidateDir validates every known evidence file in dir. A missing required
// file is reported as an issue; a missing optional file is skipped and does
// not appear in the result. The error is for I/O problems other than
// "file not found", such as a permission error.
func (v *Validator) ValidateDir(dir string) ([]FileResult, error) {
	var results []FileResult
	for _, name := range v.Files() {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			if optional[name] {
				continue
			}
			results = append(results, FileResult{File: name, Issues: []Issue{{Message: "file is missing"}}})
			continue
		}
		if err != nil {
			return nil, err
		}
		issues, err := v.Validate(name, data)
		if err != nil {
			return nil, err
		}
		results = append(results, FileResult{File: name, Issues: issues})
	}
	return results, nil
}

var printer = message.NewPrinter(language.English)

// collectLeaves flattens the library's error tree. Inner nodes only say
// "validation failed"; the leaves carry the specific, useful messages.
func collectLeaves(e *jsonschema.ValidationError, out *[]Issue) {
	if len(e.Causes) == 0 {
		*out = append(*out, Issue{
			Path:    pointer(e.InstanceLocation),
			Message: e.ErrorKind.LocalizedString(printer),
		})
		return
	}
	for _, c := range e.Causes {
		collectLeaves(c, out)
	}
}

// pointer turns ["summary", "failed"] into "/summary/failed" (RFC 6901).
func pointer(tokens []string) string {
	var sb strings.Builder
	for _, t := range tokens {
		t = strings.ReplaceAll(t, "~", "~0")
		t = strings.ReplaceAll(t, "/", "~1")
		sb.WriteString("/" + t)
	}
	return sb.String()
}
