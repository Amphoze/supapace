package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/nft"
)

// Exit statuses of `nft load` and `nft check`, one per error class of the nft
// package. Any status but 0 means the node's tables are not verified.
const (
	exitAbsent     = 3 // a table is not installed
	exitDrift      = 4 // the file or the installed tables differ from the last load
	exitBridgeNF   = 5 // a bridge-nf-call switch is on
	exitUnverified = 6 // nft could not be run, failed or timed out
)

func init() { commands["nft"] = nftCmd }

func nftCmd(args []string) int {
	if len(args) != 1 || (args[0] != "load" && args[0] != "check") {
		fmt.Fprintln(stderr, "usage: supapaced nft load|check")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if args[0] == "load" {
		if err := nft.Load(ctx, paths); err != nil {
			return nftFail("load", err)
		}
		fmt.Fprintln(stdout, "nft: tables loaded")
		return 0
	}
	if err := nft.Check(ctx, paths); err != nil {
		return nftFail("check", err)
	}
	fmt.Fprintln(stdout, "nft: tables verified")
	return 0
}

// nftFail prints err as one line and returns the status of its class.
func nftFail(verb string, err error) int {
	code := 1
	for _, c := range []struct {
		err  error
		code int
	}{{nft.ErrAbsent, exitAbsent}, {nft.ErrDrift, exitDrift}, {nft.ErrBridgeNF, exitBridgeNF}, {nft.ErrUnverified, exitUnverified}} {
		if errors.Is(err, c.err) {
			code = c.code
			break
		}
	}
	// nft's own stderr can span lines; the message stays one line.
	fmt.Fprintf(stderr, "supapaced nft %s: %s\n", verb, strings.Join(strings.Fields(err.Error()), " "))
	return code
}
