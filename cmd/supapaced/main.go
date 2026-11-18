// Command supapaced is the node daemon. Each subcommand lives in its own file
// and registers itself in commands from an init function.
package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// commands maps a subcommand name to its entry point, which returns the exit
// status: 0 success, 1 failure, 2 usage.
var commands = map[string]func(args []string) int{}

// The node's paths and standard streams; tests substitute their own.
var (
	paths  nodecfg.Paths
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		if cmd, ok := commands[args[0]]; ok {
			return cmd(args[1:])
		}
	}
	names := make([]string, 0, len(commands))
	for k := range commands {
		names = append(names, k)
	}
	slices.Sort(names)
	fmt.Fprintf(stderr, "usage: supapaced %s ...\n", strings.Join(names, "|"))
	return 2
}
