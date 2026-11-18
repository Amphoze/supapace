package main

import (
	"io"
	"net/http"
	"testing"
)

// The success lines the grammar names that no other test reaches.
func TestS3_RemainingSuccessLines(t *testing.T) {
	f := newS3Fake(t)
	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter, r s3Req)
		args   []string
		out    string
	}{
		{"versioning never set", func(w http.ResponseWriter, r s3Req) {
			io.WriteString(w, "<VersioningConfiguration></VersioningConfiguration>")
		}, []string{"versioning"}, "versioning off\n"},
		{"versioning suspended", func(w http.ResponseWriter, r s3Req) {
			io.WriteString(w, "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>")
		}, []string{"versioning"}, "versioning Suspended\n"},
		{"no lock configuration", func(w http.ResponseWriter, r s3Req) {
			w.WriteHeader(404)
			io.WriteString(w, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>")
		}, []string{"lock"}, "lock none\n"},
		{"lock without a default retention", func(w http.ResponseWriter, r s3Req) {
			io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")
		}, []string{"lock"}, "lock none\n"},
		{"a version removed", func(w http.ResponseWriter, r s3Req) {
			w.Header().Set("X-Amz-Version-Id", "v1")
			w.WriteHeader(204)
		}, []string{"rm", "k", "--version", "v1"}, "removed v1 marker=false\n"},
	} {
		f.answer = c.answer
		if code, out := f.run(t, c.args...); code != 0 || out != c.out {
			t.Errorf("%s: exit %d %q, want %q", c.name, code, out, c.out)
		}
	}
}
