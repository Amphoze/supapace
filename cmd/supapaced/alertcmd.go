package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/alert"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

func init() { commands["alert"] = alertCmd }

func alertCmd(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return alertSet(args[1:])
		case "show":
			return alertShow(args[1:])
		case "test":
			return alertSendCode("test", "test", args[1:])
		case "send":
			return alertSend(args[1:])
		}
	}
	fmt.Fprintln(stderr, "usage: supapaced alert send|set|show|test ...")
	return 2
}

// alertFail prints the command's error on one line and returns 1.
func alertFail(cmd string, err error) int {
	msg := strings.ReplaceAll(err.Error(), "alert: ", "")
	fmt.Fprintf(stderr, "supapaced alert %s: %s\n", cmd, strings.Join(strings.Fields(msg), " "))
	return 1
}

func alertRoot(cmd string) bool {
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "supapaced alert %s: must run as root\n", cmd)
		return false
	}
	return true
}

// alertSet saves the destination, its CA bundle and the dead-man template.
// It makes no request: `alert test` delivers the first document.
func alertSet(args []string) int {
	fl := flag.NewFlagSet("alert set", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var d alert.Declaration
	var urlFile, deadmanFile, caFile, oldURL, oldDeadman string
	fl.StringVar(&urlFile, "url-file", "", "file holding the https://host[:port][/path][?query] the documents are posted to (required)")
	fl.StringVar(&caFile, "ca-file", "", "CA bundle (PEM) for the destination and the dead-man address, in place of the system's roots")
	fl.StringVar(&deadmanFile, "deadman-url-file", "", "file holding the dead-man address template, with {stanza}, requested with GET")
	fl.StringVar(&oldURL, "url", "", "not accepted: use --url-file")
	fl.StringVar(&oldDeadman, "deadman-url", "", "not accepted: use --deadman-url-file")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	for flag, set := range map[string]bool{"--url": oldURL != "", "--deadman-url": oldDeadman != ""} {
		if set {
			fmt.Fprintf(stderr, "supapaced alert set: %s is not accepted: the address may hold a token; give it in a file with %s-file\n", flag, flag)
			return 2
		}
	}
	if fl.NArg() != 0 || urlFile == "" {
		fmt.Fprintln(stderr, "supapaced alert set: --url-file is required, and nothing else may follow the flags")
		fl.Usage()
		return 2
	}
	if !alertRoot("set") {
		return 1
	}
	var err error
	if d.URL, err = alert.ReadAddressFile(urlFile); err != nil {
		return alertFail("set", fmt.Errorf("--url-file: %w", err))
	}
	if deadmanFile != "" {
		if d.DeadmanURL, err = alert.ReadAddressFile(deadmanFile); err != nil {
			return alertFail("set", fmt.Errorf("--deadman-url-file: %w", err))
		}
	}
	if caFile != "" {
		f, err := os.Open(caFile)
		if err != nil {
			return alertFail("set", err)
		}
		b, err := io.ReadAll(io.LimitReader(f, 1<<20))
		f.Close()
		if err != nil {
			return alertFail("set", err)
		}
		d.CAPEM = string(b)
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return alertFail("set", err)
	}
	defer clear(k[:])
	if err := alert.Save(paths, k, d); err != nil {
		return alertFail("set", err)
	}
	dm := "not declared"
	if d.DeadmanURL != "" {
		dm = alert.Redact(d.DeadmanURL)
	}
	fmt.Fprintf(stdout, "supapaced alert set: wrote %s; destination %s, dead-man %s (paths and queries not shown); run supapaced alert test to deliver a first document\n",
		paths.AlertSealed(), alert.Redact(d.URL), dm)
	return 0
}

// alertShow prints the declaration without the addresses' paths and
// queries; an undeclared node is not an error and needs no key.
func alertShow(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: supapaced alert show")
		return 2
	}
	if !alertRoot("show") {
		return 1
	}
	var d alert.Declaration
	if _, err := os.Lstat(paths.AlertSealed()); !errors.Is(err, fs.ErrNotExist) {
		k, err := loadKEK(paths.KEK())
		if err != nil {
			return alertFail("show", err)
		}
		defer clear(k[:])
		if d, _, err = alert.Load(paths, k); err != nil {
			return alertFail("show", err)
		}
	}
	if d.URL == "" {
		fmt.Fprintln(stdout, "destination: not declared")
	} else {
		ca, dm := "the system's roots", "not declared"
		if d.CAPEM != "" {
			ca = "the declared bundle"
		}
		if d.DeadmanURL != "" {
			dm = alert.Redact(d.DeadmanURL) + " (path and query not shown)"
		}
		fmt.Fprintf(stdout, "destination: %s (path and query not shown)\nCA: %s\ndead-man: %s\n", alert.Redact(d.URL), ca, dm)
	}
	if r := d.NotReady(); r != "" {
		fmt.Fprintf(stdout, "alert gate for real data: not met: %s\n", r)
	} else {
		fmt.Fprintln(stdout, "alert gate for real data: met")
	}
	return 0
}

// alertSend sends one document of a listed code for the node, straight from
// the sealed file: no daemon and no database. A code off the list is
// refused, so a unit's instance name cannot put a text of its choosing in a
// document.
func alertSend(args []string) int {
	fl := flag.NewFlagSet("alert send", flag.ContinueOnError)
	fl.SetOutput(stderr)
	code := fl.String("code", "", "the alert code (required)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 || *code == "" {
		fmt.Fprintln(stderr, "supapaced alert send: --code is required, and nothing else may follow the flags")
		return 2
	}
	return alertSendCode("send", *code, nil)
}

// alertSendCode is `alert send` and `alert test`; the test, once delivered,
// is recorded in the declaration file.
func alertSendCode(cmd, code string, rest []string) int {
	if len(rest) != 0 {
		fmt.Fprintln(stderr, "usage: supapaced alert test")
		return 2
	}
	sev, known := alert.Severity(code)
	if !known {
		fmt.Fprintf(stderr, "supapaced alert %s: %.64q is not an alert code\n", cmd, code)
		return 2
	}
	if !alertRoot(cmd) {
		return 1
	}
	c, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		return alertFail(cmd, err)
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return alertFail(cmd, err)
	}
	defer clear(k[:])
	d, ok, err := alert.Load(paths, k)
	if err != nil {
		return alertFail(cmd, err)
	}
	if !ok {
		fmt.Fprintf(stderr, "supapaced alert %s: no alert destination declared; run supapaced alert set --url-file F first\n", cmd)
		return 1
	}
	now := time.Now().UTC()
	doc := alert.Document{Node: c.NodeID, Subject: "node", Code: code, Severity: sev, Count: 1, FirstAt: now, LastAt: now}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := alert.NewSender(nil, c.NodeID, nil).Send(ctx, d, doc); err != nil {
		fmt.Fprintf(stderr, "supapaced alert %s: not delivered: %s\n", cmd, strings.TrimPrefix(err.Error(), "alert: "))
		return 1
	}
	if cmd == "test" {
		if err := alert.MarkTested(paths, k, d); err != nil {
			fmt.Fprintf(stderr, "supapaced alert test: delivered to %s, but not recorded: %s\n", alert.Redact(d.URL), strings.TrimPrefix(err.Error(), "alert: "))
			return 1
		}
	}
	fmt.Fprintf(stdout, "supapaced alert %s: %s delivered to %s\n", cmd, code, alert.Redact(d.URL))
	return 0
}
