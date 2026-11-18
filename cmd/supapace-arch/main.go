// Command supapace-arch is the cluster's archive and restore command; see
// package arch. It is built static and mounted read-only into the cluster.
package main

import (
	"os"

	"github.com/Amphoze/supapace/internal/arch"
)

func main() { os.Exit(arch.Main(os.Args, os.Stderr)) }
