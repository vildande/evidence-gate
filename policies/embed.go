// bundle the policies into the binary, so check works without a policies directory
package policies

import "embed"

//go:embed *.rego
var FS embed.FS
