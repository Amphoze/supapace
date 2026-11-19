package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

func init() { subcommands["limits"] = limits }

func limits(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("limits", flag.ContinueOnError)
	fs.SetOutput(stderr)
	names := fs.Bool("names", false, "print the fixed and the listener environment names")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: sp-dashstub limits [--names]")
		return 2
	}
	if !*names {
		fmt.Fprintln(stdout, dashcfg.Limits.StudioJSON())
		return 0
	}
	b, _ := json.Marshal(struct {
		Fixed    []string `json:"fixed"`
		Listener []string `json:"listener"`
	}{dashcfg.FixedEnvNames(), dashcfg.ListenerNames})
	fmt.Fprintln(stdout, string(b))
	return 0
}
