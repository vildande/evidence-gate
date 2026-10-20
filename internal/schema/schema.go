// Package schema validates evidence files against JSON Schemas before they are used by policies. 
// Сatches missing fields, typos, and invalid values early.
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

// schemaFor maps each evidence file to the schema
var schemaFor = map[string]string{
	"test-report.json": "test-report.schema.json",
	"waivers.json":     "waivers.schema.json",
}

// optional evidence files. A project might not have waivers, for example
var optional = map[string]bool{
	"waivers.json": true,
}

// represents validation problem 
type Issue struct {
	Path    string	// path to value in json doc
	Message string
}

// format issue to readable string
func (i Issue) String() string {
	if i.Path == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

// stores already compiled schemas
type Validator struct {
	schemas map[string]*jsonschema.Schema // key is evidence file name, value is emebedded schema objects
}


// create validator
func New() (*Validator, error) {
	// third-party library that compiles and validates JSON schemas
	c := jsonschema.NewCompiler() 

	// reuse the format from the library, which has already format for "date-time" and "uri" and so on
	c.AssertFormat()

	v := &Validator{schemas: make(map[string]*jsonschema.Schema)}
	for evidenceFile, schemaFile := range schemaFor {
		data, err := fs.ReadFile(schemas.FS, schemaFile) // read the embedded schema files
		if err != nil {
			return nil, fmt.Errorf("read schema %s: %w", schemaFile, err)
		}

		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data)) // parse the schema into a document (for the library to understand)
		if err != nil {
			return nil, fmt.Errorf("parse schema %s: %w", schemaFile, err)
		}

		// the compiler identifies schemas by URL
		url := "file:///schemas/" + schemaFile
		if err := c.AddResource(url, doc); err != nil {
			return nil, fmt.Errorf("add schema %s: %w", schemaFile, err)
		}

		// prepare schemas, they will be used for validation
		compiled, err := c.Compile(url) 
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", schemaFile, err)
		}
		v.schemas[evidenceFile] = compiled
	}
	return v, nil
}

// return names of evidence files, sorted by file name
func (v *Validator) Files() []string {
	return slices.Sorted(maps.Keys(v.schemas))
}


// check the evidence file using the corresponding schema
func (v *Validator) Validate(fileName string, data []byte) ([]Issue, error) {
	// get schema
	sch, ok := v.schemas[fileName]
	if !ok {
		return nil, fmt.Errorf("no schema for evidence file %q", fileName)
	}

	// json -> document
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return []Issue{{Message: "not valid JSON: " + err.Error()}}, nil
	}

	// validate document against schema. if no error, stop
	err = sch.Validate(doc)
	if err == nil {
		return nil, nil
	}

	// if its validation error, continue, otherwise return the error
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return nil, err
	}

	// collect the errors from error tree, sort them by path
	var issues []Issue
	collectLeaves(verr, &issues)
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	return issues, nil
}

// outcome of validating a single file
type FileResult struct {
	File   string
	Issues []Issue
}


// validate all files in the directory 
func (v *Validator) ValidateDir(dir string) ([]FileResult, error) {
	// check the directory exists and whether it is a directory
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("evidence directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("evidence directory: %s is not a directory", dir)
	}

	// go through all the files for which we have schemas
	var results []FileResult
	for _, name := range v.Files() { 
		data, err := os.ReadFile(filepath.Join(dir, name)) // read the evidence file in directory

		// if not-found error, record and continue to next file. if file is optional, skip error
		if errors.Is(err, fs.ErrNotExist) {
			if optional[name] {
				continue
			}
			results = append(results, FileResult{File: name, Issues: []Issue{{Message: "file is missing"}}}) 
			continue
		}

		// if any other error, return it
		if err != nil {
			return nil, err
		}

		// validate the evidence file against the schema
		issues, err := v.Validate(name, data)
		if err != nil {
			return nil, err
		}

		// add result for this file
		results = append(results, FileResult{File: name, Issues: issues})
	}
	return results, nil
}


// setting the messages to English
var printer = message.NewPrinter(language.English)

// collect the errors from the error tree
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

// turns ["summary", "failed"] into "/summary/failed" 
func pointer(tokens []string) string {
	var sb strings.Builder
	for _, t := range tokens {
		t = strings.ReplaceAll(t, "~", "~0") // "~" -> "~0" (RFC 6901)
		t = strings.ReplaceAll(t, "/", "~1") // "/" -> "~1" (RFC 6901)
		sb.WriteString("/" + t)
	}
	return sb.String()
}
