// bundle/embed the JSON Schemas into the binary, so files arent necessary
package schemas

import "embed"

//go:embed *.schema.json
var FS embed.FS
