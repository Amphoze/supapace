// Command pgcap is the platform's wire proxy between shared services and every
// project's database server. Its one argument is the path of its table, which it
// re-reads when the file changes.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Amphoze/supapace/internal/pgcap"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: pgcap TABLE")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := pgcap.Run(ctx, args[0], stderr); err != nil {
		fmt.Fprintln(stderr, "pgcap:", err)
		return 1
	}
	return 0
}
