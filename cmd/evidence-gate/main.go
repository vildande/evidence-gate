// evidence-gate checks CI evidence against JSON Schemas and Rego policies.
//
//	evidence-gate collect --test-json f --coverage f --project p --commit c --out f
//	evidence-gate check --evidence dir [--policies dir] [--json] [--summary file]
//	evidence-gate version
//
// exit codes: 0 pass | 1 policy failure | 2 invalid or missing evidence, or any error
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const (
	exitPass  = 0
	exitFail  = 1
	exitError = 2
)

// set at release: go build -ldflags "-X main.version=v1.0.0"
var version = "dev"

const usage = `usage:
  evidence-gate collect --test-json f --coverage f --project p --commit c --out f
  evidence-gate check --evidence dir [--policies dir] [--json] [--summary file]
  evidence-gate version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without os.Exit, so tests can call it and check the exit code
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}

	switch args[0] {
	case "collect":
		return runCollect(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "evidence-gate", version)
		return exitPass
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitPass
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitError
	}
}

// -h prints the flags and is not an error; any other flag problem is
func parseExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitPass
	}
	return exitError
}
