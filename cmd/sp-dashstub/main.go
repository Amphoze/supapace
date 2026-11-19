// Command sp-dashstub holds the dashboard's stand-ins for tests and for the
// Studio build:
//
//	sp-dashstub limits [--names]   Studio's SUPAPACE_LIMITS value; with --names,
//	                               {"fixed": [...], "listener": [...]}: the
//	                               environment names the agent always sets and
//	                               the listener names an image may declare
//
// Each sub-command lives in its own file and registers itself in subcommands.
// Usage errors exit 2.
package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// subcommands maps a name to its entry point, which takes the arguments after
// the name and returns the exit status.
var subcommands = map[string]func(args []string, stdout, stderr io.Writer) int{}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if f, ok := subcommands[args[0]]; ok {
			return f(args[1:], stdout, stderr)
		}
	}
	var names []string
	for n := range subcommands {
		names = append(names, n)
	}
	slices.Sort(names)
	fmt.Fprintf(stderr, "usage: sp-dashstub %s …\n", strings.Join(names, "|"))
	return 2
}
