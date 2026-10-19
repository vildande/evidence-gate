// Package schemas bundles the evidence JSON Schemas into the binary, so a
// downloaded evidence-gate works without the repository checked out next to it.
package schemas

import "embed"

// go:embed only sees files in this directory or below, which is why this
// file lives next to the schemas instead of in internal/schema.
//
//go:embed *.schema.json
var FS embed.FS
