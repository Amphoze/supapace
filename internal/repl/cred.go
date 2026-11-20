package repl

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/s3x"
)

// Keys is one access key and its secret. It prints as a placeholder under
// every fmt verb, so no error or log line can carry it.
type Keys struct{ Access, Secret string }

func (Keys) String() string                 { return "repl.Keys{…}" }
func (k Keys) GoString() string             { return k.String() }
func (k Keys) Format(f fmt.State, _ rune)   { io.WriteString(f, k.String()) }
func (Keys) MarshalJSON() ([]byte, error)   { return []byte(`"…"`), nil }
func (k Keys) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// credMax bounds the credential file: two pairs of keys with room to spare.
const credMax = 4096

// ReadCred reads the credential file once: exactly pairs pairs of lines,
// access key then secret key, no blank line, no space or control byte; a
// regular file, opened without following a link or blocking. A copy or
// rebuild job holds one pair, a probe two (the write pair, then the read-only
// pair): a file of another shape is another role's and is refused. No error
// quotes the file.
func ReadCred(path string, pairs int) ([]Keys, error) {
	b, err := readSmall(path, credMax)
	if err != nil {
		return nil, fmt.Errorf("repl: the credential file: %w", err)
	}
	defer clear(b)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(b) == 0 || len(lines) != 2*pairs {
		return nil, fmt.Errorf("repl: the credential file does not hold exactly %d key pair(s)", pairs)
	}
	for _, l := range lines {
		for i := 0; i < len(l); i++ {
			if l[i] <= ' ' || l[i] > 0x7e { // printable ASCII only, as the keys files of the declaration
				return nil, errors.New("repl: the credential file holds a space, a control byte or a blank line")
			}
		}
		if l == "" {
			return nil, errors.New("repl: the credential file holds a blank line")
		}
	}
	out := make([]Keys, pairs)
	for i := range out {
		out[i] = Keys{lines[2*i], lines[2*i+1]}
	}
	return out, nil
}

// readSmall reads a regular file of at most max bytes, without following a
// link or blocking on a FIFO.
func readSmall(path string, max int64) ([]byte, error) {
	fd, err := syscall.Open(path, readFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("not a regular file of at most %d bytes", max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("longer than %d bytes", max)
	}
	return b, err
}

// Env is the job's environment as the launcher writes it. It holds no
// secret: the keys are in the credential file.
type Env struct {
	Endpoint, Region, Bucket, Prefix, OtherBucket string
	PathStyle                                     bool
	Addrs                                         []netip.AddrPort
}

// ErrNoAddrs: the launcher handed no address. With none the client would
// resolve the endpoint's name itself, which a job never does.
var ErrNoAddrs = errors.New("repl: no address of the endpoint was handed to the job")

// addrsMax bounds the address set (the resolver keeps at most 16; the
// addresses file at most 256).
const addrsMax = 256

// secretWords mark an environment name that may carry a secret: a job of
// this program holds none in its environment, so one there means the job was
// given another role's environment.
var secretWords = []string{"PASS", "SECRET", "KEY", "TOKEN"}

// ReadEnv reads the job's environment (environ as os.Environ gives it).
func ReadEnv(environ []string) (Env, error) {
	get := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		for _, w := range secretWords {
			if strings.Contains(strings.ToUpper(k), w) {
				return Env{}, fmt.Errorf("repl: the environment holds %.64q: a secret never reaches this job that way", k)
			}
		}
		get[k] = v
	}
	e := Env{Endpoint: get["SUPAPACE_S3_ENDPOINT"], Region: get["SUPAPACE_S3_REGION"], Bucket: get["SUPAPACE_S3_BUCKET"],
		Prefix: get["SUPAPACE_S3_PREFIX"], OtherBucket: get["SUPAPACE_S3_OTHER_BUCKET"]}
	switch get["SUPAPACE_S3_PATH_STYLE"] {
	case "1":
		e.PathStyle = true
	case "0":
	default:
		return Env{}, errors.New("repl: SUPAPACE_S3_PATH_STYLE is neither 1 nor 0")
	}
	if !validPrefix(e.Prefix) {
		return Env{}, errors.New("repl: SUPAPACE_S3_PREFIX breaks the key rule")
	}
	list := get["SUPAPACE_S3_ADDRS"]
	if list == "" {
		return Env{}, ErrNoAddrs
	}
	for _, s := range strings.Split(list, ",") {
		a, err := netip.ParseAddrPort(s)
		if err != nil || !a.Addr().Is4() || a.Port() == 0 || len(e.Addrs) == addrsMax {
			return Env{}, fmt.Errorf("repl: SUPAPACE_S3_ADDRS: %.64q is not an IPv4 address and port, or more than %d", s, addrsMax)
		}
		e.Addrs = append(e.Addrs, a)
	}
	return e, nil
}

// CallTimeout bounds one call of the client, from the dial to the last byte:
// a part of 32 MiB at about 0.6 MiB/s, so one stuck call cannot take a
// program's whole bound.
const CallTimeout = 60 * time.Second

// The program's own time bounds, below its job's deadline (bklimit.Deadline),
// so that it always ends with a result line that records what it did: an
// upload cut by the bound fails and the copy stops upload-failed. cleanupMax
// bounds the aborts and deletes that run after a cut.
const (
	CopyBound  = 240 * time.Second // copy and rebuild; their job kind is replicate
	ProbeBound = 100 * time.Second
	cleanupMax = 10 * time.Second
)

// Bound is the time bound of mode (copy, rebuild, probe).
func Bound(mode string) time.Duration {
	if mode == "probe" {
		return ProbeBound
	}
	return CopyBound
}

// ErrInput marks an input the program refuses: the code input.
var ErrInput = errors.New("repl: input")

// Codes are the failure codes the program prints for a job of kind
// (replicate: copy and rebuild; probe), the one list of them.
func Codes(kind string) []string {
	switch kind {
	case "replicate":
		return []string{"input", "credential", "index", "repository", "store", "result"}
	case "probe":
		return []string{"input", "credential", "store", "result"}
	}
	return nil
}

// Config is the client configuration for bucket under k: only the handed
// addresses, the endpoint's name for TLS and Host alone.
func (e Env) Config(bucket string, k Keys, ca string) s3x.Config {
	return s3x.Config{Endpoint: e.Endpoint, Region: e.Region, Bucket: bucket, PathStyle: e.PathStyle,
		AccessKey: k.Access, SecretKey: k.Secret, CAPEM: ca, Addrs: e.Addrs, Timeout: CallTimeout}
}

// ReadCA reads the declared CA bundle, "" when there is none.
func ReadCA(path string) (string, error) {
	b, err := readSmall(path, 64<<10)
	if errors.Is(err, syscall.ENOENT) {
		return "", nil
	}
	return string(b), err
}

// Bucket is one bucket's client with its declared prefix: the Store of the
// program.
type Bucket struct {
	*s3x.Client
	prefix string
}

func NewBucket(c *s3x.Client, prefix string) Bucket { return Bucket{c, prefix} }

func (b Bucket) Prefix() string { return b.prefix }
