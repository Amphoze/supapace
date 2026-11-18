package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Amphoze/supapace/internal/rmtree"
)

func init() { commands["rmtree"] = rmtreeCmd }

// rmtreeCmd removes each PATH, in order, with rmtree.Remove, or empties it
// with rmtree.Empty under --keep-root. It runs inside a project's task
// container at the project's uid, where this binary is the only file of the
// platform: it reads no configuration. Nothing is printed on success; the
// first failure is one line on stderr and exit 1. Every PATH is checked
// before the first is touched; rmtree refuses to run as uid 0.
func rmtreeCmd(args []string) int {
	fl := flag.NewFlagSet("rmtree", flag.ContinueOnError)
	fl.SetOutput(stderr)
	keep := fl.Bool("keep-root", false, "empty each PATH but keep the directory itself")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	args = fl.Args()
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: supapaced rmtree [--keep-root] PATH...")
		return 2
	}
	for _, a := range args {
		if !filepath.IsAbs(a) || filepath.Clean(a) != a || a == "/" {
			fmt.Fprintf(stderr, "supapaced rmtree: path %s is not an absolute, clean path below /\n", strconv.QuoteToASCII(a))
			return 2
		}
	}
	remove := rmtree.Remove
	if *keep {
		remove = rmtree.Empty
	}
	for _, a := range args {
		if err := remove(a); err != nil {
			fmt.Fprintf(stderr, "supapaced %v\n", err) // err starts with "rmtree: "
			return 1
		}
	}
	return 0
}
