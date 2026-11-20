package repl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	testAccess = "test-access-key-one"
	testSecret = "test-secret-value-0123456789"
)

func credFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(body), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

// The keys come from the credential file, read once, and never print: no
// environment name may carry one.
func TestCred_ReadOnceFromTheFile_NothingSecretInTheEnvironment(t *testing.T) {
	p := credFile(t, testAccess+"\n"+testSecret)
	k, err := ReadCred(p, 1)
	if err != nil || len(k) != 1 || k[0] != (Keys{testAccess, testSecret}) {
		t.Fatalf("%v %v", k, err)
	}
	// Read once: the file can go, the keys stay.
	os.Remove(p)
	if k[0].Secret != testSecret {
		t.Fatal("keys changed")
	}
	var log strings.Builder
	slog.New(slog.NewJSONHandler(&log, nil)).Info("x", "keys", k[0], "list", k)
	slog.New(slog.NewTextHandler(&log, nil)).Info("x", "keys", k[0])
	j, _ := json.Marshal(k)
	for _, s := range []string{fmt.Sprint(k[0]), fmt.Sprintf("%v %+v %#v %s %q %x %d", k[0], k[0], k[0], k[0], k[0], k[0], k), log.String(), string(j)} {
		if strings.Contains(s, testSecret) || strings.Contains(s, testAccess) {
			t.Errorf("a key printed: %s", s)
		}
	}
	// The environment of the job holds the location only; a name that could carry a secret refuses the job.
	good := []string{"PATH=/usr/bin", "HOSTNAME=x", "SUPAPACE_S3_ENDPOINT=https://s3.example.test", "SUPAPACE_S3_REGION=r",
		"SUPAPACE_S3_BUCKET=b", "SUPAPACE_S3_PREFIX=p", "SUPAPACE_S3_PATH_STYLE=1", "SUPAPACE_S3_ADDRS=192.0.2.10:443,192.0.2.11:443"}
	e, err := ReadEnv(good)
	if err != nil || len(e.Addrs) != 2 || !e.PathStyle {
		t.Fatalf("%+v %v", e, err)
	}
	for _, extra := range []string{"PGBACKREST_REPO1_CIPHER_PASS=x", "AWS_SECRET_ACCESS_KEY=" + testSecret, "AWS_ACCESS_KEY_ID=x",
		"SUPAPACE_S3_SECRET_KEY=x", "aws_session_token=x"} {
		_, err := ReadEnv(append(good, extra))
		if err == nil {
			t.Errorf("accepted %s", extra)
		} else if strings.Contains(err.Error(), testSecret) {
			t.Errorf("the refusal quotes the value: %v", err)
		}
	}
	if c := e.Config("b", k[0], ""); fmt.Sprint(c.Addrs) != fmt.Sprint(e.Addrs) || c.AccessKey != testAccess {
		t.Errorf("config %v", c.Addrs)
	}
}

// A copy or rebuild holds one key pair, a probe two; any other shape is
// another role's file, and none at all is refused. No refusal quotes it.
func TestCred_RefusesAnotherRolesShapeOrNone(t *testing.T) {
	two := testAccess + "\n" + testSecret + "\n" + testAccess + "R\n" + testSecret + "R\n"
	for _, c := range []struct {
		body  string
		pairs int
	}{
		{"", 1}, {testAccess + "\n", 1}, {two, 1}, {testAccess + "\n" + testSecret, 2},
		{testAccess + "\n\n" + testSecret, 1}, {testAccess + " \n" + testSecret, 1}, {testAccess + "\n" + testSecret + "\x00", 1},
		{"PGBACKREST_REPO1_CIPHER_PASS=" + testSecret, 1},
		{testAccess + "\n" + testSecret + "\xc3\xa9", 1}, // a byte outside printable ASCII
		{strings.Repeat("a", 5000) + "\n" + testSecret, 1},
	} {
		_, err := ReadCred(credFile(t, c.body), c.pairs)
		if err == nil {
			t.Errorf("accepted %.40q for %d pair(s)", c.body, c.pairs)
		} else if strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), testAccess) {
			t.Errorf("the refusal quotes the file: %v", err)
		}
	}
	if k, err := ReadCred(credFile(t, two), 2); err != nil || k[1].Access != testAccess+"R" {
		t.Errorf("control: %v", err)
	}
	if _, err := ReadCred(filepath.Join(t.TempDir(), "none"), 1); err == nil {
		t.Error("accepted no file")
	}
	// A link to a credential, and a FIFO, are refused without following or blocking.
	dir := t.TempDir()
	os.Symlink(credFile(t, testAccess+"\n"+testSecret), filepath.Join(dir, "link"))
	syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600)
	for _, n := range []string{"link", "fifo"} {
		if _, err := ReadCred(filepath.Join(dir, n), 1); err == nil {
			t.Errorf("accepted the %s", n)
		}
	}
}

func TestEnv_Bounds(t *testing.T) {
	base := []string{"SUPAPACE_S3_PATH_STYLE=0", "SUPAPACE_S3_PREFIX="}
	if _, err := ReadEnv(base); !errors.Is(err, ErrNoAddrs) {
		t.Errorf("no addresses: %v", err)
	}
	many := make([]string, 257)
	for i := range many {
		many[i] = fmt.Sprintf("192.0.2.%d:443", i%250+1)
	}
	for _, a := range []string{"[2001:db8::1]:443", "192.0.2.1", "192.0.2.1:0", "s3.example.test:443", "192.0.2.1:443,", strings.Join(many, ",")} {
		if _, err := ReadEnv(append(base, "SUPAPACE_S3_ADDRS="+a)); err == nil {
			t.Errorf("accepted %.60q", a)
		}
	}
	for _, kv := range []string{"SUPAPACE_S3_PATH_STYLE=yes", "SUPAPACE_S3_PREFIX=/p"} {
		if _, err := ReadEnv(append([]string{"SUPAPACE_S3_PATH_STYLE=0", "SUPAPACE_S3_ADDRS=192.0.2.1:443"}, kv)); err == nil {
			t.Errorf("accepted %s", kv)
		}
	}
}

// A FIFO that a writer feeds valid keys is still not the credential file.
func TestCred_AFedFifoIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	// Held open read-write, the pipe already holds the keys when the program opens it.
	w, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.WriteString(testAccess + "\n" + testSecret)
	if _, err := ReadCred(p, 1); err == nil {
		t.Error("read keys from a FIFO")
	}
}
