package main

import (
	"os"
	"testing"
)

func TestAlertSet_RefusesAnArgumentAfterTheFlags(t *testing.T) {
	n := newAlertNode(t)
	if code, _, _ := n.runClean("alert", "set", "--url-file", n.file("https://h.example.test/x"), "extra"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Lstat(n.p.AlertSealed()); err == nil {
		t.Fatal("written")
	}
}
