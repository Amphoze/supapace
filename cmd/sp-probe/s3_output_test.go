package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A store-chosen error code on a bucket call reaches the verdict line only as
// plain characters.
func TestS3_RawErrorCodePlain(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.WriteHeader(500)
		io.WriteString(w, "<Error><Code>Bad\u009b31mCodé</Code></Error>")
	}
	code, out := f.run(t, "versioning")
	if code != exitError || strings.ContainsAny(out, "\u009bé") {
		t.Errorf("exit %d %q", code, out)
	}
}
