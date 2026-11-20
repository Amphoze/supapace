package adminapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

type auditT struct {
	Ref     string `json:"ref"`
	Records []struct {
		T         string `json:"t"`
		Ref       string `json:"ref"`
		Iss       string `json:"iss"`
		Sub       string `json:"sub"`
		Role      string `json:"role"`
		Login     string `json:"login"`
		Kind      string `json:"kind"`
		SQLSHA256 string `json:"sql_sha256"`
	} `json:"records"`
	Skipped   int  `json:"skipped"`
	Truncated bool `json:"truncated"`
}

func auditLine(sub string) string {
	return `{"t":"2026-11-19T10:00:00.000Z","ref":"` + demoRef + `","iss":"https://id.example.test","sub":"` + sub +
		`","role":"developer","login":"supabase_developer","kind":"query","sql_sha256":"` + strings.Repeat("ab", 32) + `"}` + "\n"
}

// auditDir creates the project's directory in the dashboard's data volume.
func (e *env) auditDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(dashcfg.PathsFor(e.p).DataDir(), demoRef)
	must(t, os.MkdirAll(dir, 0o700))
	return dir
}

func (e *env) audit(t *testing.T, query string) auditT {
	t.Helper()
	var a auditT
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/audit"+query, "", 200), &a)
	return a
}

func subs(a auditT) string {
	var s []string
	for _, r := range a.Records {
		s = append(s, r.Sub)
	}
	return strings.Join(s, ",")
}

func TestAudit_FileIsUntrusted(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	// No directory yet: nothing recorded.
	if a := e.audit(t, ""); a.Ref != demoRef || len(a.Records) != 0 || a.Skipped != 0 || a.Truncated {
		t.Fatalf("%+v", a)
	}
	dir := e.auditDir(t)
	write := func(name, s string) { must(t, os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600)) }
	write("audit.log.1", auditLine("a")+auditLine("b"))
	write("audit.log", auditLine("c")+auditLine("d")+auditLine("e"))
	if a := e.audit(t, ""); subs(a) != "a,b,c,d,e" || a.Truncated || a.Skipped != 0 || a.Records[0].SQLSHA256 != strings.Repeat("ab", 32) ||
		a.Records[0].Kind != "query" || a.Records[0].Login != "supabase_developer" || a.Records[0].T != "2026-11-19T10:00:00.000Z" {
		t.Fatalf("%+v", a)
	}
	// tail keeps the newest.
	if a := e.audit(t, "?tail=2"); subs(a) != "d,e" || !a.Truncated {
		t.Fatalf("%+v", a)
	}
	if a := e.audit(t, "?tail=1000"); subs(a) != "a,b,c,d,e" {
		t.Fatalf("%+v", a)
	}
	for _, q := range []string{"?tail=0", "?tail=1001", "?tail=-1", "?tail=x", "?tail=1&tail=2", "?n=1", "?tail="} {
		e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit"+q, "", 400, "bad_request")
	}
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000/audit", "", 404, "not_found")

	// Lines that are not a record are counted, not shown; text is cleaned.
	typegen := `{"t":"2026-11-19T10:00:00.000Z","ref":"` + demoRef + `","iss":"i","sub":"tg","role":"owner","login":"l","kind":"typegen"}` + "\n"
	write("audit.log.1", "")
	write("audit.log", strings.Join([]string{
		auditLine("ok1"),
		"not json\n",
		`["an","array"]` + "\n",
		`{"t":"x"}` + "\n", // members missing
		strings.TrimSuffix(auditLine("extra"), "}\n") + `,"more":1}` + "\n",
		strings.Replace(auditLine("num"), `"role":"developer"`, `"role":7`, 1),
		strings.Replace(auditLine("dup"), `"role":"developer"`, `"role":"developer","role":"owner"`, 1),
		auditLine(strings.Repeat("x", 4097)),
		auditLine(`esc\u001b[31mred‮evil\u0000`),
		typegen,
		auditLine("last-without-newline")[:len(auditLine("last-without-newline"))-1],
	}, ""))
	a := e.audit(t, "")
	if subs(a) != "ok1,esc[31mredevil,tg,last-without-newline" || a.Skipped != 7 {
		t.Fatalf("%q skipped %d", subs(a), a.Skipped)
	}
	if a.Records[2].SQLSHA256 != "" {
		t.Fatalf("%+v", a.Records[2])
	}

	// A link in place of the file is not followed.
	outside := filepath.Join(t.TempDir(), "secret")
	write("audit.log.1", "")
	must(t, os.WriteFile(outside, []byte(auditLine("leaked")), 0o600))
	must(t, os.Remove(filepath.Join(dir, "audit.log")))
	must(t, os.Symlink(outside, filepath.Join(dir, "audit.log")))
	eb := e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit", "", 409, "conflict")
	if strings.Contains(eb.Message, "leaked") || !strings.Contains(eb.Message, "not a regular file") {
		t.Fatalf("%q", eb.Message)
	}
	// Not a regular file: a directory, a FIFO (which must not block).
	must(t, os.Remove(filepath.Join(dir, "audit.log")))
	must(t, os.Mkdir(filepath.Join(dir, "audit.log"), 0o700))
	e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit", "", 409, "conflict")
	must(t, os.Remove(filepath.Join(dir, "audit.log")))
	must(t, syscall.Mkfifo(filepath.Join(dir, "audit.log.1"+".tmp"), 0o600))
	must(t, os.Rename(filepath.Join(dir, "audit.log.1"+".tmp"), filepath.Join(dir, "audit.log.1")))
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit", "", 409, "conflict")
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		// Unblock the reader so the test can end, then fail.
		if f, err := os.OpenFile(filepath.Join(dir, "audit.log.1"), os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		t.Fatal("a FIFO in place of the file held the request")
	}
	must(t, os.Remove(filepath.Join(dir, "audit.log.1")))

	// A link in place of the project's directory is not followed.
	elsewhere := t.TempDir()
	must(t, os.WriteFile(filepath.Join(elsewhere, "audit.log"), []byte(auditLine("leaked")), 0o600))
	must(t, os.RemoveAll(dir))
	must(t, os.Symlink(elsewhere, dir))
	eb = e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit", "", 409, "conflict")
	if strings.Contains(eb.Message, "leaked") {
		t.Fatalf("%q", eb.Message)
	}
	// Control: the same files in a real directory are read.
	must(t, os.Remove(dir))
	must(t, os.Rename(elsewhere, dir))
	if a := e.audit(t, ""); subs(a) != "leaked" {
		t.Fatalf("%+v", a)
	}
}

// The files are read up to 16 MiB together, the newest bytes first.
func TestAudit_ReadBound(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	dir := e.auditDir(t)
	line := auditLine("old")
	var b strings.Builder
	b.WriteString("beyond the bound: never read\n")
	for b.Len() < 9<<20 {
		b.WriteString(line)
	}
	old := b.String()
	must(t, os.WriteFile(filepath.Join(dir, "audit.log.1"), []byte(old), 0o600))
	var cur strings.Builder
	for cur.Len() < 9<<20 {
		cur.WriteString(line)
	}
	for i := range 3 {
		cur.WriteString(auditLine(fmt.Sprint("new", i)))
	}
	must(t, os.WriteFile(filepath.Join(dir, "audit.log"), []byte(cur.String()), 0o600))
	a := e.audit(t, "?tail=3")
	if subs(a) != "new0,new1,new2" || !a.Truncated {
		t.Fatalf("%q %+v", subs(a), a.Truncated)
	}
	a = e.audit(t, "?tail=1000")
	if len(a.Records) != 1000 || !a.Truncated || a.Skipped != 0 {
		t.Fatalf("%d records, skipped %d", len(a.Records), a.Skipped)
	}
}

// A record of another project is not the project's; a file with a second
// name (a hard link) is not read.
func TestAudit_OtherRefAndHardLink(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	dir := e.auditDir(t)
	other := strings.Replace(auditLine("other"), `"ref":"`+demoRef+`"`, `"ref":"zzzz0000000000000000"`, 1)
	must(t, os.WriteFile(filepath.Join(dir, "audit.log"), []byte(auditLine("mine")+other), 0o600))
	if a := e.audit(t, ""); subs(a) != "mine" || a.Skipped != 1 {
		t.Fatalf("%q skipped %d", subs(a), a.Skipped)
	}
	outside := filepath.Join(dir, "elsewhere")
	must(t, os.WriteFile(outside, []byte(auditLine("linked")), 0o600))
	must(t, os.Remove(filepath.Join(dir, "audit.log")))
	must(t, os.Link(outside, filepath.Join(dir, "audit.log")))
	eb := e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/audit", "", 409, "conflict")
	if strings.Contains(eb.Message, "linked") {
		t.Fatalf("%q", eb.Message)
	}
	must(t, os.Remove(outside)) // control: one name again
	if a := e.audit(t, ""); subs(a) != "linked" {
		t.Fatalf("%+v", a)
	}
}
